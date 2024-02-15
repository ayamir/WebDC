# WebUDP

WebRTC datachannel library and server forked from [seemk/WebUDP](https://github.com/seemk/WebUDP)

The library implements a minimal subset of WebRTC to achieve unreliable and out of order UDP transfer for browser clients.
See the [echo server example](https://github.com/seemk/WebUDP/blob/master/examples) for how to connect to the server from a browser.
The core library (Wu) is platform independent. Refer to `WuHostEpoll` or `WuHostNode` for platform-specific usage.

## Developing

```bash
bash ./generate_clangd.sh # generate .clangd file for clangd-based editor
```

## Building

```bash
mkdir build && cd build
cmake ..
make -j
```

### Host platforms

- Linux (epoll)
- Node.js `-DWITH_NODE=ON`

### Issues

- Firefox doesn't connect to a server running on localhost. Bind a different interface.
