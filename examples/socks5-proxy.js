const {createServer} = require('./src/socks5')

const server = createServer()

server.listen(1088, () => console.log('listen at 1088'))
