const {
  checkVersion,
  getDistInfo
} = require('../src/socks5')

describe('Test socks5', () => {
  describe('Test function checkVersion', () => {
    it('Should return false when buffer size lt 2', () => {
      expect(checkVersion(Buffer.from([0x05]))).toBe(false)
    })
    it('Should return false when the first byte is not 0x05', () => {
      expect(checkVersion(Buffer.from([0x01, 0x00]))).toBe(false)
    })
    it('Should return true when buffer format suits rfc1928', () => {
      expect(checkVersion(Buffer.from([0x05, 0x00]))).toBe(true)
    })
  })

  describe('Test function getDistInfo', () => {
    it('Should return dist info when atype is ipv4', () => {
      const ipv4 = [0x7F, 0x00, 0x00, 0x01]
      const input = Buffer.from([0x05, 0x01, 0x00, 0x01, ...ipv4, 0x00, 0x50])
      const dist = getDistInfo(input)
      expect(dist.addr).toBe('127.0.0.1')
      expect(dist.port).toBe(80)
    })
    it('Should return dist info when atype is domain', () => {
      const host = 'www.bing.com'
      const domain = Buffer.concat([
        Buffer.from([host.length]),
        Buffer.from(host)
      ])
      const input = Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03]),
        domain,
        Buffer.from([0x00, 0x50])
      ])
      const dist = getDistInfo(input)
      expect(dist.addr).toBe(host)
      expect(dist.port).toBe(80)
    })
    it('Should return dist info when atype is ipv6', () => {
      const ipv6 = [0x04, 0x1A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02, 0x58, 0xff, 0xff, 0xff, 0xff]
      const input = Buffer.from([0x05, 0x01, 0x00, 0x04, ...ipv6, 0x00, 0x50])
      const dist = getDistInfo(input)
      expect(dist.port).toBe(80)
    })
  })
})
