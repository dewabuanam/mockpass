const express = require('express')
const fs = require('fs')
const { render } = require('mustache')
const jose = require('node-jose')
const path = require('path')

const assertions = require('../assertions')
const { generateAuthCode, lookUpByAuthCode } = require('../auth-code')

const LOGIN_TEMPLATE = fs.readFileSync(
  path.resolve(__dirname, '../../static/html/login-page.html'),
  'utf8',
)

const VERSION_PREFIX = '/v2'
const OAUTH_PREFIX = '/oauth'
const PATH_PREFIX = VERSION_PREFIX + OAUTH_PREFIX

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../../static/certs/spcp-key.pem'),
)

const idGenerator = {
  singPass: ({ nric }, myinfo) =>
    myinfo.v3.personas[nric] ? `${nric} [MyInfo]` : nric,
}

const buildAssertURL = (redirectURI, authCode, state) =>
  `${redirectURI}?code=${encodeURIComponent(
    authCode,
  )}&state=${encodeURIComponent(state)}`

async function config(app, { showLoginPage, serviceProvider, isStateless }) {
  const profiles = await assertions.fetchSingpass()
  const defaultProfile =
    profiles.find((p) => p.nric === process.env.MOCKPASS_NRIC) || profiles[0]

  app.get(`${PATH_PREFIX}/authorize`, async (req, res) => {
    const { redirect_uri: redirectURI, state, nonce } = req.query
    const scopes = req.query.scope ?? 'openid'
    console.info(`Requested scope ${scopes}`)
    let myinfo = await assertions.fetchMyInfo()
    if (showLoginPage(req)) {
      const values = profiles
        .filter((profile) => myinfo.v3.personas[profile.nric])
        .map((profile) => {
          const authCode = generateAuthCode(
            { profile, scopes, nonce },
            { isStateless },
          )
          const assertURL = buildAssertURL(redirectURI, authCode, state)
          const id = idGenerator.singPass(profile, myinfo)
          return { id, assertURL }
        })
      const response = render(LOGIN_TEMPLATE, { values })
      res.send(response)
    } else {
      const profile = defaultProfile
      const authCode = generateAuthCode(
        { profile, scopes, nonce },
        { isStateless },
      )
      const assertURL = buildAssertURL(redirectURI, authCode, state)
      console.info(
        `Redirecting login from ${req.query.client_id} to ${assertURL}`,
      )
      res.redirect(assertURL)
    }
  })

  app.post(
    `${PATH_PREFIX}/token`,
    express.json(),
    express.urlencoded({ extended: true }),
    async (req, res) => {
      console.log(req.body)
      const { client_id: aud, code: authCode } = req.body

      console.info(
        `Received auth code ${authCode} from ${aud} and ${req.body.redirect_uri}`,
      )

      try {
        const { profile, scopes, nonce } = lookUpByAuthCode(authCode, {
          isStateless,
        })
        console.info(
          `Profile ${JSON.stringify(profile)} with token scope ${scopes}`,
        )
        const accessToken = authCode
        const iss = `${req.protocol}://${req.get('host') + VERSION_PREFIX}`

        const { idTokenClaims, refreshToken } = assertions.oidc.create.singPass(
          profile,
          iss,
          aud,
          nonce,
          accessToken,
        )
        // Change sub from `s=${nric},u=${uuid}`
        // to `u=${uuid}` to be consistent with userinfo sub
        idTokenClaims.sub = idTokenClaims.sub.split(',')[1]

        const signingKey = await jose.JWK.asKey(signingPem, 'pem')
        const idToken = await jose.JWS.createSign(
          { format: 'compact' },
          signingKey,
        )
          .update(JSON.stringify(idTokenClaims))
          .final()

        res.json({
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 24 * 60 * 60,
          scope: scopes,
          token_type: 'Bearer',
          id_token: idToken,
        })
      } catch (error) {
        console.error(error)
        res.status(500).json({ message: error.message })
      }
    },
  )

  app.get(`${PATH_PREFIX}/userinfo`, async (req, res) => {
    const authCode = (
      req.headers.authorization || req.headers.Authorization
    ).replace('Bearer ', '')
    // eslint-disable-next-line no-unused-vars
    const { profile, scopes, unused } = lookUpByAuthCode(authCode, {
      isStateless,
    })
    const uuid = profile.uuid
    const nric = assertions.oidc.singPass.find((p) => p.uuid === uuid).nric
    let myinfo = await assertions.fetchMyInfo()
    const persona = myinfo.v3.personas[nric]

    console.info(`userinfo scopes ${scopes}`)
    const payloadKey = await jose.JWK.createKey('oct', 256, {
      alg: 'A256GCM',
    })

    const encryptPayload = async (field) => {
      return await jose.JWE.createEncrypt({ format: 'compact' }, payloadKey)
        .update(field)
        .final()
    }
    const encryptedNric = await encryptPayload(nric)
    // sgID doesn't actually offer the openid scope yet
    const scopesArr = scopes
      .split(' ')
      .filter((field) => field !== 'openid' && field !== 'myinfo.nric_number')
    console.info(`userinfo scopesArr ${scopesArr}`)
    const myInfoFields = await Promise.all(
      scopesArr.map((scope) =>
        encryptPayload(sgIDScopeToMyInfoField(persona, scope)),
      ),
    )

    const data = {}
    scopesArr.forEach((name, index) => {
      data[name] = myInfoFields[index]
    })
    data['myinfo.nric_number'] = encryptedNric
    const encryptionKey = await jose.JWK.asKey(serviceProvider.pubKey, 'pem')

    const plaintextPayloadKey = JSON.stringify(payloadKey.toJSON(true))
    const encryptedPayloadKey = await jose.JWE.createEncrypt(
      { format: 'compact' },
      encryptionKey,
    )
      .update(plaintextPayloadKey)
      .final()
    res.json({
      sub: `u=${uuid}`,
      key: encryptedPayloadKey,
      data,
    })
  })

  app.get(`${VERSION_PREFIX}/.well-known/jwks.json`, async (_req, res) => {
    const key = await jose.JWK.asKey(signingPem, 'pem')
    const jwk = key.toJSON()
    jwk.use = 'sig'
    res.json({ keys: [jwk] })
  })

  app.get(
    `${VERSION_PREFIX}/.well-known/openid-configuration`,
    async (req, res) => {
      const issuer = `${req.protocol}://${req.get('host') + VERSION_PREFIX}`

      res.json({
        issuer,
        authorization_endpoint: `${issuer}/${OAUTH_PREFIX}/authorize`,
        token_endpoint: `${issuer}/${OAUTH_PREFIX}/token`,
        userinfo_endpoint: `${issuer}/${OAUTH_PREFIX}/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        // Note: some of these scopes are not yet officially documented
        // in https://docs.id.gov.sg/data-catalog
        // So they are not officially supported yet.
        scopes_supported: [
          'openid',
          'myinfo.nric_number',
          'myinfo.name',
          'myinfo.email',
          'myinfo.sex',
          'myinfo.race',
          'myinfo.mobile_number',
          'myinfo.registered_address',
          'myinfo.date_of_birth',
          'myinfo.passport_number',
          'myinfo.passport_expiry_date',
          'myinfo.nationality',
          'myinfo.residentialstatus',
          'myinfo.residential',
          'myinfo.housingtype',
          'myinfo.hdbtype',
          'myinfo.birth_country',
          'myinfo.vehicles',
          'myinfo.name_of_employer',
          'myinfo.workpass_status',
          'myinfo.workpass_expiry_date',
          'myinfo.marital_status',
          'myinfo.mobile_number_with_country_code',
        ],
        id_token_signing_alg_values_supported: ['RS256'],
        subject_types_supported: ['pairwise'],
      })
    },
  )
}

const concatMyInfoRegAddr = (regadd) => {
  const line1 =
    !!regadd.block.value || !!regadd.street.value
      ? `${regadd.block.value} ${regadd.street.value}`
      : ''
  const line2 =
    !!regadd.floor.value || !!regadd.unit.value
      ? `#${regadd.floor.value}-${regadd.unit.value}`
      : ''
  const line3 =
    !!regadd.country.desc || !!regadd.postal.value
      ? `${regadd.country.desc} ${regadd.postal.value}`
      : ''
  return `${line1}\n${line2}\n${line3}`
}

// Refer to sgid myinfo parser
const formatMobileNumberWithPrefix = (phone) => {
  if (!phone || !phone.nbr?.value) {
    return 'NA'
  }
  return phone.prefix?.value && phone.areacode?.value
    ? `${phone.prefix?.value}${phone.areacode?.value} ${phone.nbr?.value}`
    : phone.nbr?.value
}

// Refer to sgid myinfo parser
const formatVehicles = (vehicles) => {
  const vehicleObjects =
    vehicles?.map((vehicle) => ({
      vehicle_number: vehicle.vehicleno?.value || 'NA',
    })) || '[]'
  return vehicleObjects
}

const formatJsonStringify = (value) => {
  return value == undefined ? 'NA' : JSON.stringify(value)
}

const defaultUndefinedToNA = (value) => {
  return value || 'NA'
}

// Refer to https://docs.id.gov.sg/data-catalog
const sgIDScopeToMyInfoField = (persona, scope) => {
  switch (scope) {
    // No NRIC as that is always returned by default
    case 'openid':
      return defaultUndefinedToNA(persona.uuid?.value)
    case 'myinfo.name':
      return defaultUndefinedToNA(persona.name?.value)
    case 'myinfo.email':
      return defaultUndefinedToNA(persona.email?.value)
    case 'myinfo.sex':
      return defaultUndefinedToNA(persona.sex?.desc)
    case 'myinfo.race':
      return defaultUndefinedToNA(persona.race?.desc)
    case 'myinfo.mobile_number':
      return defaultUndefinedToNA(persona.mobileno?.nbr?.value)
    case 'myinfo.registered_address':
      return concatMyInfoRegAddr(persona.regadd)
    case 'myinfo.date_of_birth':
      return defaultUndefinedToNA(persona.dob?.value)
    case 'myinfo.passport_number':
      return defaultUndefinedToNA(persona.passportnumber?.value)
    case 'myinfo.passport_expiry_date':
      return defaultUndefinedToNA(persona.passportexpirydate?.value)
    case 'myinfo.nationality':
      return defaultUndefinedToNA(persona.nationality?.desc)
    case 'myinfo.residentialstatus':
      return defaultUndefinedToNA(persona.residentialstatus?.desc)
    case 'myinfo.residential':
      return defaultUndefinedToNA(persona.residential?.desc)
    case 'myinfo.housingtype':
      return defaultUndefinedToNA(persona.housingtype?.desc)
    case 'myinfo.hdbtype':
      return defaultUndefinedToNA(persona.hdbtype?.desc)
    case 'myinfo.birth_country':
      return defaultUndefinedToNA(persona.birthcountry?.desc)
    case 'myinfo.vehicles':
      return formatVehicles(persona.vehicles)
    case 'myinfo.name_of_employer':
      return defaultUndefinedToNA(persona.employment?.value)
    case 'myinfo.workpass_status':
      return defaultUndefinedToNA(persona.passstatus?.value)
    case 'myinfo.workpass_expiry_date':
      return defaultUndefinedToNA(persona.passexpirydate?.value)
    case 'myinfo.marital_status':
      return defaultUndefinedToNA(persona.marital?.desc)
    case 'myinfo.mobile_number_with_country_code':
      return formatMobileNumberWithPrefix(persona.mobileno)
    case 'pocdex.public_officer_details':
      return formatJsonStringify(persona.publicofficerdetails)
    default:
      return 'NA'
  }
}

module.exports = config
