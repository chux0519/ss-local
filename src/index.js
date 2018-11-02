const {createServer: createSocksServer} = require('node-socks5')
const {buildLocalProxy} = require('./ss-local')

function createServer (options) {
  const onProxy = buildLocalProxy(options)
  const server = createSocksServer({onProxy})
  return server
}

module.exports = createServer
