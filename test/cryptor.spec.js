const stream = require('stream')
const {buildCryptor, evpBytesToKey} = require('../src/cryptor')

describe('Test crypto', () => {
  const pass = 'key'
  const uniqKey = '3c6e0b8a9c15224a8228b9a98ca1531dd1e2a35fba509b6432edb96d850e119f'
  describe('Test buildCryptor', () => {
    const cryptor = buildCryptor(pass)
    it('Should has the same key', () => {
      expect(cryptor.key.toString('hex')).toBe(uniqKey)
    })

    it('Should descrypt buffer which is encrypted by itself', () => {
      const input = 'hello, world'
      const encrypted = cryptor.encode(Buffer.from(input))
      const decrypted = cryptor.decode(encrypted)
      expect(decrypted.toString('utf8')).toBe(input)
    })

    it('Should works with stream', async () => {
      const content = 'hello, world'
      const buf = Buffer.from(content, 'utf8')

      // encrypt
      const encryptInStream = new stream.PassThrough()
      encryptInStream.push(buf)
      encryptInStream.push(null)
      const encryptOutStream = new stream.PassThrough()
      encryptInStream.pipe(cryptor.cipher).pipe(encryptOutStream)
      const encryptedPromise = new Promise(resolve => {
        let chunks = []
        encryptOutStream.on('data', chunk => chunks.push(chunk))
        encryptOutStream.on('end', () => resolve(Buffer.concat(chunks)))
      })
      const encrypted = await encryptedPromise

      // decrypt
      const decryptInStream = new stream.PassThrough()
      decryptInStream.push(encrypted)
      decryptInStream.push(null)
      const decryptOutStream = new stream.PassThrough()
      decryptInStream.pipe(cryptor.decipher).pipe(decryptOutStream)
      const decryptedPromise = new Promise(resolve => {
        let chunks = []
        decryptOutStream.on('data', chunk => chunks.push(chunk))
        decryptOutStream.on('end', () => resolve(Buffer.concat(chunks)))
      })
      const decrypted = await decryptedPromise
      expect(decrypted.toString('utf8')).toBe(content)
    })
  })
  describe('Test evpBytesToKey', () => {
    it('Should return exact key when using the EVP_BytesToKey algo', () => {
      const [key, _] = evpBytesToKey(pass) // eslint-disable-line
      expect(key.toString('hex')).toBe(uniqKey)
    })
  })
})
