const crypto = require('crypto')

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

module.exports = { evpBytesToKey }
