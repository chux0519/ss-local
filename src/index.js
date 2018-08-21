const {buildLocalProxy} = require('./ss-local')
const {createServer: createSocksServer} = require('./socks5')

function createServer (options) {
  const onProxy = buildLocalProxy(options)
  const server = createSocksServer({onProxy})
  return server
}

module.exports = createServer
