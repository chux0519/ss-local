# ss-local

A minimal shadowsocks client implemented by nodejs.

Because of using [stream.pipeline](https://nodejs.org/dist/latest-v10.x/docs/api/stream.html#stream_stream_pipeline_streams_callback), node version must be greater than 10.

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
