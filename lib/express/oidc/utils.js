const buildAssertURL = (redirectURI, authCode, state) =>
  `${redirectURI}?code=${encodeURIComponent(
    authCode,
  )}&state=${encodeURIComponent(state)}`

const idGenerator = {
  singPass: ({ nric, name }, myinfo) =>
    myinfo.v3.personas[nric]
      ? `${myinfo.v3.personas[nric].name.value} (${nric}) [MyInfo]`
      : `${name} (${nric})`,
  corpPass: ({ nric, uen, name }) => `${name} (${nric}) / UEN: ${uen}`,
}

const customProfileFromHeaders = {
  singPass: (req) => {
    const customNricHeader = req.header('X-Custom-NRIC')
    const customUuidHeader = req.header('X-Custom-UUID')
    if (!customNricHeader || !customUuidHeader) {
      return false
    }
    return { nric: customNricHeader, uuid: customUuidHeader }
  },
  corpPass: (req) => {
    const customNricHeader = req.header('X-Custom-NRIC')
    const customUuidHeader = req.header('X-Custom-UUID')
    const customUenHeader = req.header('X-Custom-UEN')
    if (!customNricHeader || !customUuidHeader || !customUenHeader) {
      return false
    }
    return {
      nric: customNricHeader,
      uuid: customUuidHeader,
      uen: customUenHeader,
    }
  },
}

module.exports = {
  buildAssertURL,
  idGenerator,
  customProfileFromHeaders,
}
