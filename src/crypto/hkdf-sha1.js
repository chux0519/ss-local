const crypto = require('crypto')

const ALGORITHM = 'sha1'
const DIGEST_SIZE = 20 // 20 bytes

class HKDFSha1 {
  constructor (options) {
    const { salt, inputKeyMaterial } = options
    const hmac = crypto.createHmac(ALGORITHM, toBuffer(salt))
    hmac.update(toBuffer(inputKeyMaterial))
    this._prk = hmac.digest()
  }

  expand (info, len = 32) {
    return hkdfExpand(this._prk, info, len)
  }
}

/**
 * hkdfExpand
 * @returns Buffer
 * @param {*} pseudoRandKey 
 * @param {*} info 
 * @param {*} length 
 */
function hkdfExpand (pseudoRandKey, info, length) {
  if (length > 255 * DIGEST_SIZE) throw new Error(`Cannot expand to more than 255 * ${DIGEST_SIZE} = ${255 * DIGEST_SIZE} bytes using the specified hash function`)
  const blocks = Math.floor(length / DIGEST_SIZE) + (length % DIGEST_SIZE === 0 ? 0 : 1)
  let okm = ''
  let output = ''
  let counter = 0
  while (counter < blocks) {
    const hmac = crypto.createHmac(ALGORITHM, toBuffer(pseudoRandKey))
    hmac.update(Buffer.concat([
      Buffer.from(output, 'hex'),
      toBuffer(info),
      Buffer.from([counter + 1])
    ]))
    output = hmac.digest('hex')
    okm += output
    counter += 1
  }
  return fromHex(okm.slice(0, length * 2))
}

function fromHex (str) {
  return Buffer.from(str, 'hex')
}

function toBuffer (bufOrHex) {
  return Buffer.isBuffer(bufOrHex) ? bufOrHex : fromHex(bufOrHex)
}

module.exports = { HKDFSha1, hkdfExpand }
