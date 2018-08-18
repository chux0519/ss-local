const {evpBytesToKey} = require('../src/cryptor')

describe('Test crypto', () => {
  const pass = 'key'
  const uniqKey = '3c6e0b8a9c15224a8228b9a98ca1531dd1e2a35fba509b6432edb96d850e119f'
  describe('Test evpBytesToKey', () => {
    it('Should return exact key when using the EVP_BytesToKey algo', () => {
      const [key, _] = evpBytesToKey(pass) // eslint-disable-line
      expect(key.toString('hex')).toBe(uniqKey)
    })
  })
})
