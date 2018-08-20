# ss-local

A minimal shadowsocks client implemented by nodejs.

Because of using [stream.pipeline](https://nodejs.org/dist/latest-v10.x/docs/api/stream.html#stream_stream_pipeline_streams_callback), node version must be greater than 10.

ps: This is an unstable poc project, might be rewrite after some time.

## feature

- TCP support (only)
- aes-256-cfb encrytion (only, which is the default method of most of ss server)
- minimal code

## quickstart

1. install via npm

    > npm install --save ss-local

2. start local server

    ```javascript
    const serve = require('ss-local')

    serve({
      host: 'ss server host',
      port: 'ss server port',
      password: 'password',
      localPort: 'ss local port' // 1088 by default
    })
    ```

3. test via curl

    curl 7.54.0 (x86_64-apple-darwin17.0) libcurl/7.54.0 LibreSSL/2.0.20 zlib/1.2.11 nghttp2/1.24.0
    > curl https://github.com/ --socks5 127.0.0.1:1088