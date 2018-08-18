const {buildLocalProxy} = require('./ss-local')
const {createServer} = require('./socks5')

const LOCAL_PORT = 1088

function serve (options) {
  const {host, port, password, localPort = LOCAL_PORT} = options
  const onProxy = buildLocalProxy({host, port, password})
  const server = createServer({onProxy})
  server.listen(localPort, () => console.log(`listen at ${localPort}`))
}

module.exports = serve
