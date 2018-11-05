const crypto = require('crypto')
const { HKDFSha1 } = require('./hkdf-sha1')
const { evpBytesToKey } = require('./evp')

const CIPHERS = {
  // AEAD: iv_len = salt_len = key_len
  'chacha20-ietf-poly1305': {
    keyLen: 32,
    ivLen: 32,
    nonceLen: 12,
    tagLen: 16,
    isAEAD: true,
    name: 'chacha20-poly1305'
  },
  'aes-256-gcm': {
    keyLen: 32,
    ivLen: 32,
    nonceLen: 12,
    tagLen: 16,
    isAEAD: true,
    name: 'aes-256-gcm'
  }
}
const SS_INFO = Buffer.from('ss-subkey')

class AEADCryptor {
  constructor (method, password, key = null, encryptIV = null, decryptIV = null) {
    if (!password) throw new Error('Cryptor: password required')
    const { keyLen, ivLen, tagLen, nonceLen, name } = CIPHERS[method] || {}
    if (!keyLen || !ivLen || !tagLen || !nonceLen) throw new Error(`Cryptor: method ${method} is not supported`)
    this._password = password
    this._method = name
    this._keyLen = keyLen
    this._ivLen = ivLen
    this._tagLen = tagLen
    this._nonceLen = nonceLen
    this._encNonce = Buffer.alloc(nonceLen, 0)
    this._decNonce = Buffer.alloc(nonceLen, 0)
    this._encIKM = key || evpBytesToKey(password, keyLen, ivLen)[0]
    this._decIKM = this._encIKM
    this._encSault = encryptIV || crypto.randomBytes(ivLen) // sault
    this._decSault = decryptIV
    this._encSubKey = new HKDFSha1({
      salt: this._encSault,
      inputKeyMaterial: this._encIKM})
      .expand(SS_INFO, keyLen)
    this._decSubKey = null
    this._cipher = crypto.createCipheriv(this._method, this._encSubKey, this._encNonce)
    this._decipher = null
    this._remain = null
  }
  encode (chunk) {
    // TCP Chunk (after encryption, *ciphertext*)
    // +--------------+---------------+--------------+------------+
    // |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
    // +--------------+---------------+--------------+------------+
    // |      2       |     Fixed     |   Variable   |   Fixed    |
    // +--------------+---------------+--------------+------------+
    const len = Buffer.alloc(2)
    len.writeInt16BE(chunk.length)
    const dataLen = this._cipher.update(len)
    const dataLenFinal = this._cipher.final()
    const dataLenTag = this._cipher.getAuthTag()
    this.incEncNonce()
    this.reInitCipher()
    const data = this._cipher.update(chunk)
    const dataFinal = this._cipher.final()
    const dataTag = this._cipher.getAuthTag()
    this.incEncNonce()
    this.reInitCipher()
    return Buffer.concat([
      dataLen, dataLenFinal, dataLenTag,
      data, dataFinal, dataTag
    ])
  }
  decode (chunk) {
    // remains from last chunk
    if (this._remain) chunk = Buffer.concat([this._remain, chunk])

    // decode data len
    const dataLenChunk = chunk.slice(0, 2)
    const dataLenTag = chunk.slice(2, 2 + this._tagLen)
    this._decipher.setAuthTag(dataLenTag)
    const dataLen = Buffer.concat([
      this._decipher.update(dataLenChunk),
      this._decipher.final()
    ]).readInt16BE(0)
    this.incDecNonce()
    this.reInitDecipher()

    // decode data
    const dataStart = 2 + this._tagLen
    const dataTagStart = dataStart + dataLen
    const remainStart = dataTagStart + this._tagLen

    const dataChunk = chunk.slice(dataStart, dataStart + dataLen)
    console.log('rcv: ', dataLen)
    const dataTag = chunk.slice(dataTagStart, dataTagStart + this._tagLen)
    this._decipher.setAuthTag(dataTag)
    const data = Buffer.concat([
      this._decipher.update(dataChunk),
      this._decipher.final()
    ])
    this.incDecNonce()
    this.reInitDecipher()

    // save remains
    console.log('remain: ', remainStart)
    this._remain = chunk.slice(remainStart)
    return data
  }
  incEncNonce () {
    nonceIncrement(this._encNonce, this._nonceLen)
  }
  reInitCipher () {
    this._cipher = crypto.createCipheriv(this._method, this._encSubKey, this._encNonce)
  }
  incDecNonce () {
    nonceIncrement(this._decNonce, this._nonceLen)
  }
  reInitDecipher () {
    this._decipher = crypto.createDecipheriv(this._method, this._decSubKey, this._decNonce)
  }
  get encryptIV () { return this._encSault }
  set decryptIV (iv) {
    if (!iv) throw new Error('iv is requried')
    if (this._decipher || this._decSault) throw new Error('decryptIV exists')
    this._decSault = iv
    this._decSubKey = new HKDFSha1({
      salt: this._decSault,
      inputKeyMaterial: this._decIKM})
      .expand(SS_INFO, this._keyLen)
    this._decipher = crypto.createDecipheriv(this._method, this._decSubKey, this._decNonce)
  }
}

/**
 * nonceIncrement
 * @param {*} nonce Buffer
 * @param {*} len Number
 */
function nonceIncrement (nonce, len) {
  let c = 1
  for (let i = 0; i < len; ++i) {
    c += nonce.readUInt8(i)
    nonce.writeUInt8(c & 0xff, i)
    c >>= 8
  }
}

module.exports = {
  AEADCryptor,
  nonceIncrement,
  AEAD_CIPHERS: CIPHERS
}
