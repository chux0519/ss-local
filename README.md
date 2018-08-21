# ss-local

A minimal shadowsocks local server implemented by nodejs.

Because of using [stream.pipeline](https://nodejs.org/dist/latest-v10.x/docs/api/stream.html#stream_stream_pipeline_streams_callback), node version must be greater than 10.

ps: This is an unstable poc project, might be rewrite after some time.

## feature

- TCP support (only)
- mutiple [cipher](#ciphers) supported
- minimal code

## quickstart

1. install via npm

    > npm install --save ss-local

2. start local server

    ```javascript
    const createServer = require('ss-local')

    const server = createServer({
      host: '127.0.0.1',
      port: 8388,
      password: 'chuxss',
      method: 'aes-256-cfb'
    })

    server.listen(1088, () => { console.log('serve at 1088') })
    ```

3. test via curl

    curl 7.54.0 (x86_64-apple-darwin17.0) libcurl/7.54.0 LibreSSL/2.0.20 zlib/1.2.11 nghttp2/1.24.0
    > curl https://github.com/ --socks5 127.0.0.1:1088

## ciphers

Most ciphers recommended [here](https://shadowsocks.org/en/spec/Stream-Ciphers.html) are supported.

- [x] aes-128-ctr
- [x] aes-192-ctr
- [x] aes-256-ctr
- [x] aes-128-cfb
- [x] aes-192-cfb
- [x] aes-256-cfb
- [x] camellia-128-cfb
- [x] camellia-192-cfb
- [x] camellia-256-cfb
- [ ] chacha20-ietf
