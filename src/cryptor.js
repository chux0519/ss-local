const crypto = require('crypto')

const KEY_LEN = 32
const IV_LEN = 16

const addIV = (iv, buf) => Buffer.concat([iv, buf])

function buildCryptor (password) {
  const [key, _] = evpBytesToKey(password) // eslint-disable-line
  const iv = crypto.randomBytes(IV_LEN)
  const cipher = crypto.createCipheriv('aes-256-cfb', key, iv)
  const decipher = crypto.createDecipheriv('aes-256-cfb', key, iv)

  // for buffer
  const encode = buf => encodeBuffer(key, iv, buf)
  const decode = buf => decodeBuffer(key, iv, buf)

  return {
    key,
    iv,
    cipher, // for stream
    decipher, // for stream
    encode, // for buffer
    decode // for buffer
  }
}

function encodeBuffer (key, iv, buf) {
  const cipher = crypto.createCipheriv('aes-256-cfb', key, iv)
  return Buffer.concat([cipher.update(buf), cipher.final()])
}

function decodeBuffer (key, iv, buf) {
  const decipher = crypto.createDecipheriv('aes-256-cfb', key, iv)
  return Buffer.concat([decipher.update(buf), decipher.final()])
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
  buildCryptor,
  evpBytesToKey
}
