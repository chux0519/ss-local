const crypto = require('crypto')

const CIPHERS = {
  'aes-128-ctr': {keyLen: 16, ivLen: 16},
  'aes-192-ctr': {keyLen: 24, ivLen: 16},
  'aes-256-ctr': {keyLen: 32, ivLen: 16},
  'aes-128-cfb': {keyLen: 16, ivLen: 16},
  'aes-192-cfb': {keyLen: 24, ivLen: 16},
  'aes-256-cfb': {keyLen: 32, ivLen: 16},
  'camellia-128-cfb': {keyLen: 16, ivLen: 16},
  'camellia-192-cfb': {keyLen: 24, ivLen: 16},
  'camellia-256-cfb': {keyLen: 32, ivLen: 16}
}

class Cryptor {
  constructor (method, password, key = null, encryptIV = null, decryptIV = null) {
    if (!password) throw new Error('Cryptor: password required')
    const {keyLen, ivLen} = CIPHERS[method] || {}
    if (!keyLen || !ivLen) throw new Error(`Cryptor: method ${method} is not supported`)
    this._password = password
    this._method = method
    this._keyLen = keyLen
    this._ivLen = ivLen
    this._key = key || evpBytesToKey(password, keyLen, ivLen)[0]
    this._encryptIV = encryptIV || crypto.randomBytes(ivLen)
    this._decryptIV = decryptIV
    this._cipher = crypto.createCipheriv(method, this._key, this._encryptIV)
    this._decipher = null
  }
  encode (chunk) {
    return this._cipher.update(chunk)
  }
  decode (chunk) {
    if (!this._decipher) throw new Error('decode: decipher not found')
    return this._decipher.update(chunk)
  }
  get encryptIV () { return this._encryptIV }
  set decryptIV (iv) {
    if (!iv) throw new Error('iv is requried')
    if (this._decipher || this._decryptIV) throw new Error('decryptIV exists')
    this._decryptIV = iv
    this._decipher = crypto.createDecipheriv(this._method, this._key, iv)
  }
}

// EVP_BytesToKey https://www.openssl.org/docs/man1.1.0/crypto/EVP_BytesToKey.html
function evpBytesToKey (password, keyLen, ivLen) {
  const pass = Buffer.from(password, 'utf8')

  let md5 = crypto.createHash('md5')
  let buf = []
  let data = pass
  let i = 0
  while (buf.length < keyLen + ivLen) {
    md5 = crypto.createHash('md5')
    data = password
    if (i > 0) data = Buffer.concat([buf[i - 1], pass])
    md5.update(data)
    buf.push(md5.digest())
    i += 1
  }
  buf = Buffer.concat(buf)
  const key = buf.slice(0, keyLen)
  const iv = buf.slice(keyLen, keyLen + ivLen)
  return [key, iv]
}

module.exports = {
  evpBytesToKey,
  Cryptor,
  CIPHERS
}
