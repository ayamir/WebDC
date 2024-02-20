# WebUDP

WebRTC datachannel library and server.

The library implements a minimal subset of WebRTC to achieve unreliable and out of order UDP transfer for browser clients.
See the [EchoServer](https://github.com/ayamir/webdc/blob/master/examples/EchoServer.c) for how to connect to the server from a browser.
The core library (Wu) is platform independent. Refer to `WuHostEpoll` or `WuHostNode` for platform-specific usage.

## Example

![image-20240216132521221](https://raw.githubusercontent.com/ayamir/blog-imgs/main/image-20240216132521221.png)

## Developing

```bash
bash ./generate_clangd.sh # generate .clangd file for clangd-based editor
```

## Building

Build passed on `openssl` `1.1.1w`.

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
