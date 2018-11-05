const createServer = require('.')

const server = createServer({
  host: '127.0.0.1',
  port: 8388,
  password: 'password',
  method: 'aes-256-gcm'
})

server.listen(1088, () => { console.log('serve at 1088') })
