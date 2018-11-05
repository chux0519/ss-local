const { nonceIncrement } = require('../src/crypto/aead')

describe('Test aead', () => {
  describe('Test nonceIncrement function', () => {
    it('Should increment 1 in little endian', () => {
      const input = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      const output = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      let inputBuf = Buffer.from(input)
      const outputBuf = Buffer.from(output)
      nonceIncrement(inputBuf, input.length)
      expect(inputBuf).toEqual(outputBuf)
    })
  })
})
