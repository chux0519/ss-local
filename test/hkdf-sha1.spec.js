const { hkdfExpand, HKDFSha1 } = require('../src/crypto/hkdf-sha1')

describe('Test hkdf-sha1', () => {
  // See https://tools.ietf.org/html/rfc5869
  // Basic test case with SHA-1

  // Hash = SHA-1
  // IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b (11 octets)
  // salt = 0x000102030405060708090a0b0c (13 octets)
  // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
  // L    = 42

  // PRK  = 0x9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243 (20 octets)
  // OKM  = 0x085a01ea1b10f36933068b56efa5ad81
  //        a4f14b822f5b091568a9cdd4f155fda2
  //        c22e422478d305f3f896 (42 octets)

  const IKM = '0b0b0b0b0b0b0b0b0b0b0b'
  const salt = '000102030405060708090a0b0c'
  const info = 'f0f1f2f3f4f5f6f7f8f9'
  const L = 42
  const PRK = '9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243'
  const OKM = '085a01ea1b10f36933068b56efa5ad81' +
              'a4f14b822f5b091568a9cdd4f155fda2' +
              'c22e422478d305f3f896'
  describe('Test constrcutor', () => {
    it('Should generate correct prk when constructed', () => {
      const hkdfSha1 = new HKDFSha1({ salt, inputKeyMaterial: IKM })
      const okm = hkdfExpand(PRK, info, L)
      const okm_ = hkdfSha1.expand(info, L)
      expect(hkdfSha1._prk.toString('hex')).toBe(PRK)
      expect(okm.toString('hex')).toBe(OKM)
      expect(okm_.toString('hex')).toBe(OKM)
    })
  })
})
