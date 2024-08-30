const crypto = require('crypto')
const fs = require('fs')
const jose = require('node-jose')
const path = require('path')
const { JsonDB, Config } = require('node-json-db')
const { v4: uuidv4 } = require('uuid')

var db = new JsonDB(new Config('db', true, false, '/'))

const signingPem = fs.readFileSync(
  path.resolve(__dirname, '../static/certs/spcp-key.pem'),
)

const hashToken = (token) => {
  const fullHash = crypto.createHash('sha256')
  fullHash.update(token, 'utf8')
  const fullDigest = fullHash.digest()
  const digestBuffer = fullDigest.slice(0, fullDigest.length / 2)
  if (Buffer.isEncoding('base64url')) {
    return digestBuffer.toString('base64url')
  } else {
    const fromBase64 = (base64String) =>
      base64String.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    return fromBase64(digestBuffer.toString('base64'))
  }
}

const fetchMyInfo = async () => {
  // Simulating fetching from JSON database
  try {
    const myinfo = await db.getData('/myinfo')
    return myinfo // Return the fetched data
  } catch (error) {
    console.error('Error fetching corpPass data:', error)
    throw error // Re-throw the error to handle it where the function is called
  }
}

const fetchCorppass = async () => {
  // Simulating fetching from JSON database
  try {
    const corppassData = await db.getData('/oidc/corppass')
    return corppassData ?? [] // Return the fetched data
  } catch (error) {
    console.error('Error fetching corpPass data:', error)
    throw error // Re-throw the error to handle it where the function is called
  }
}

const storeCorppass = async (corppassData) => {
  try {
    // Fetch existing data
    const corpPassEntries = await db.getData('/oidc/corppass')

    // Check if singpassData already exists based on 'uen' or 'nric'
    const isDuplicate = corpPassEntries.some(
      (entry) =>
        entry.uen === corppassData.uen || entry.nric === corppassData.nric,
    )

    if (isDuplicate) {
      console.log(
        'corpPassEntries data with this UEN or NRIC already exists. No changes made.',
      )
      return // Exit if duplicate is found
    }

    corppassData.uuid = uuidv4()

    corpPassEntries.push(corppassData)

    // Save the updated data back to the database
    await db.push('/oidc/corppass', corpPassEntries, true)
    console.log('Corppass data stored successfully.')
  } catch (error) {
    console.error('Error storing Corppass data:', error)
    // Optionally, handle the error more gracefully or return a specific response
    throw error
  }
}

const storeSingpass = async (singpassData) => {
  try {
    const singpassEntries = await db.getData('/oidc/singpass')

    // Check if singpassData already exists based on 'uen' or 'nric'
    const isDuplicate = singpassEntries.some(
      (entry) => entry.nric === singpassData.nric,
    )

    if (isDuplicate) {
      console.log(
        'Singpass data with this NRIC already exists. No changes made.',
      )
      return // Exit if duplicate is found
    }

    singpassData.uuid = uuidv4()

    singpassEntries.push(singpassData)

    await db.push('/oidc/singpass', singpassEntries, true)

    let myinfo = await fetchMyInfo()
    // Update or add the persona in myinfo based on the NRIC
    if (!myinfo.v3.personas[singpassData.nric]) {
      myinfo.v3.personas[singpassData.nric] = {}
    }

    myinfo.v3.personas[singpassData.nric] = {
      uuid: { value: singpassData.uuid },
      name: { value: singpassData.name },
      nric: { value: singpassData.nric },
    }

    // Optionally store the updated myinfo data back to its source if needed
    await db.push('/myinfo', myinfo, true)
    console.log('Singpass data stored successfully.')
  } catch (error) {
    console.error('Error storing Singpass data:', error)
    // Handle the error as needed or rethrow it
    throw error
  }
}

const fetchSingpassData = async () => {
  // Simulating fetching from JSON database
  try {
    let corppass = await db.getData('/oidc/singpass')
    let singpassData = corppass
    return singpassData ?? [] // Return the fetched data
  } catch (error) {
    console.error('Error fetching corpPass data:', error)
    throw error // Re-throw the error to handle it where the function is called
  }
}

const fetchSingpass = async () => {
  try {
    let knownValues = await fetchSingpassData()

    // Validate knownValues is an array or set to empty array if invalid
    let validKnownValues = Array.isArray(knownValues) ? knownValues : []
    let myinfo = await fetchMyInfo()

    let additionalValues = Object.keys(myinfo.v3.personas).map((nric) => ({
      nric,
      uuid: myinfo.v3.personas[nric].uuid.value,
    }))

    // Validate additionalValues is an array or set to empty array if invalid
    let validAdditionalValues = Array.isArray(additionalValues)
      ? additionalValues
      : []

    // If both are invalid, return empty array
    if (validKnownValues.length === 0 && validAdditionalValues.length === 0) {
      console.warn('Both knownValues and additionalValues are invalid')
      return []
    }

    // Combine known values with additional values
    let allProfiles = [...validKnownValues, ...validAdditionalValues]

    // Optionally remove duplicates based on 'nric'
    let uniqueProfiles = Array.from(
      new Set(allProfiles.map((profile) => profile.nric)),
    ).map((nric) => allProfiles.find((profile) => profile.nric === nric))

    return uniqueProfiles
  } catch (error) {
    console.error('Error retrieving profiles:', error)
    return [] // Return an empty array on error
  }
}

const oidc = {
  create: {
    singPass: (
      { nric, uuid },
      iss,
      aud,
      nonce,
      accessToken = crypto.randomBytes(15).toString('hex'),
    ) => {
      let sub
      const sfa = {
        Y4581892I: { fid: 'G730Z-H5P96', coi: 'DE', RP: 'CORPPASS' },
        Y7654321K: { fid: '123456789', coi: 'CN', RP: 'IRAS' },
        Y1234567P: { fid: 'G730Z-H5P96', coi: 'MY', RP: 'CORPPASS' },
      }
      if (nric.startsWith('Y')) {
        const sfaAccount = sfa[nric]
          ? sfa[nric]
          : { fid: 'G730Z-H5P96', coi: 'DE', RP: 'CORPPASS' }
        sub = `s=${nric},fid=${sfaAccount.fid},coi=${sfaAccount.coi},u=${uuid}`
      } else {
        sub = `s=${nric},u=${uuid}`
      }
      const accessTokenHash = hashToken(accessToken)

      const refreshToken = crypto.randomBytes(20).toString('hex')
      const refreshTokenHash = hashToken(refreshToken)

      return {
        accessToken,
        refreshToken,
        idTokenClaims: {
          rt_hash: refreshTokenHash,
          at_hash: accessTokenHash,
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
          iss,
          amr: ['pwd'],
          aud,
          sub,
          ...(nonce ? { nonce } : {}),
        },
      }
    },
    corpPass: async (
      { nric, uuid, name, isSingPassHolder, uen },
      iss,
      aud,
      nonce,
    ) => {
      const baseClaims = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
        iss,
        aud,
      }

      const sub = `s=${nric},u=${uuid},c=SG`

      const accessTokenClaims = {
        ...baseClaims,
        authorization: {
          EntityInfo: {},
          AccessInfo: {},
          TPAccessInfo: {},
        },
      }

      const signingKey = await jose.JWK.asKey(signingPem, 'pem')
      const accessToken = await jose.JWS.createSign(
        { format: 'compact' },
        signingKey,
      )
        .update(JSON.stringify(accessTokenClaims))
        .final()

      const accessTokenHash = hashToken(accessToken)

      const refreshToken = crypto.randomBytes(20).toString('hex')
      const refreshTokenHash = hashToken(refreshToken)

      return {
        accessToken,
        refreshToken,
        idTokenClaims: {
          ...baseClaims,
          rt_hash: refreshTokenHash,
          at_hash: accessTokenHash,
          amr: ['pwd'],
          sub,
          ...(nonce ? { nonce } : {}),
          userInfo: {
            CPAccType: 'User',
            CPUID_FullName: name,
            ISSPHOLDER: isSingPassHolder ? 'YES' : 'NO',
          },
          entityInfo: {
            CPEntID: uen,
            CPEnt_TYPE: 'UEN',
            CPEnt_Status: 'Registered',
            CPNonUEN_Country: '',
            CPNonUEN_RegNo: '',
            CPNonUEN_Name: '',
          },
        },
      }
    },
  },
}

module.exports = {
  oidc,
  fetchCorppass,
  fetchSingpass,
  storeCorppass,
  storeSingpass,
  fetchMyInfo,
}
