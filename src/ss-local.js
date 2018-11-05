const net = require('net')
const { pipeline, Transform } = require('stream')
const { StreamCryptor, AEADCryptor, CIPHERS } = require('./crypto')

function buildLocalProxy (options) {
  const { host, port, password, method } = options
  function onProxy (buffer, dist, sock) {
    const { isAEAD, ivLen } = CIPHERS[method]
    const cryptor = isAEAD
      ? new AEADCryptor(method, password)
      : new StreamCryptor(method, password)
    const tunnel = net.createConnection(port, host, () => {
      const rep = Buffer.from(buffer)
      rep[1] = 0x00
      sock.write(rep, () => {
        // send first packet(iv + payload)
        // +-------+----------+
        // |  IV   | Payload  |
        // +-------+----------+
        // | Fixed | Variable |
        // +-------+----------+
        // payload(encrypted)
        // +--------------+---------------------+------------------+----------+
        // | Address Type | Destination Address | Destination Port |   Data   |
        // +--------------+---------------------+------------------+----------+
        // |      1       |       Variable      |         2        | Variable |
        // +--------------+---------------------+------------------+----------+
        sock.once('data', chunk => {
          const payload = cryptor.encode(Buffer.concat([
            buffer.slice(3),
            chunk
          ]))
          tunnel.write(Buffer.concat([cryptor.encryptIV, payload]), () => {
            // pipeline
            const encoder = new Transform({
              transform (chunk, encoding, callback) {
                this.push(cryptor.encode(chunk))
                callback()
              }
            })
            pipeline(sock, encoder, tunnel, err => {
              if (err) console.error(`error: sock to tunnel: ${err.toString()}`)
            })
            tunnel.once('data', chunk => {
              cryptor.decryptIV = chunk.slice(0, ivLen)
              const payload = cryptor.decode(chunk.slice(ivLen))
              sock.write(payload, () => {
                const decoder = new Transform({
                  transform (chunk, encoding, callback) {
                    this.push(cryptor.decode(chunk))
                    callback()
                  }
                })
                pipeline(tunnel, decoder, sock, err => {
                  if (err) console.error(`error: tunnel to sock: ${err.toString()}`)
                })
              })
            })
          })
        })
      })
    })

    tunnel.once('error', console.error)
  }
  return onProxy
}

module.exports = { buildLocalProxy }
