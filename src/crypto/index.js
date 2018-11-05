const { StreamCryptor, STREAM_CIPHERS } = require('./stream')
const { AEADCryptor, AEAD_CIPHERS } = require('./aead')

module.exports = {
  StreamCryptor,
  AEADCryptor,
  CIPHERS: { ...STREAM_CIPHERS, ...AEAD_CIPHERS }
}
