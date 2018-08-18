const crypto = require('crypto')

const KEY_LEN = 32
const IV_LEN = 16

const addIV = (iv, buf) => Buffer.concat([iv, buf])
const genKeyByPass = pass => evpBytesToKey(pass)[0]

class Cryptor {
  constructor (password, key = null, encryptIV = null, decryptIV = null) {
    if (!password) throw new Error('Cryptor: password required')
    this._password = password
    this._key = key || genKeyByPass(password)
    this._encryptIV = encryptIV || crypto.randomBytes(IV_LEN)
    this._decryptIV = decryptIV
    this._cipher = crypto.createCipheriv('aes-256-cfb', this._key, this._encryptIV)
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
    this._decipher = crypto.createDecipheriv('aes-256-cfb', this._key, iv)
  }
}

// EVP_BytesToKey https://www.openssl.org/docs/man1.1.0/crypto/EVP_BytesToKey.html
function evpBytesToKey (password) {
  const pass = Buffer.from(password, 'utf8')

  let md5 = crypto.createHash('md5')
  let buf = []
  let data = pass
  let i = 0
  while (buf.length < KEY_LEN + IV_LEN) {
    md5 = crypto.createHash('md5')
    data = password
    if (i > 0) data = Buffer.concat([buf[i - 1], pass])
    md5.update(data)
    buf.push(md5.digest())
    i += 1
  }
  buf = Buffer.concat(buf)
  const key = buf.slice(0, KEY_LEN)
  const iv = buf.slice(KEY_LEN, KEY_LEN + IV_LEN)
  return [key, iv]
}

module.exports = {
  addIV,
  evpBytesToKey,
  Cryptor
}
