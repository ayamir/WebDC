# WebDC

WebRTC datachannel library and server.

The library implements a minimal subset of WebRTC to achieve unreliable and out of order UDP transfer for browser clients.
See the [EchoServer](https://github.com/ayamir/webdc/blob/master/examples/EchoServer.c) for how to connect to the server from a browser.
The core library (Dc) is platform independent. Refer to `HostEpoll` for linux-platform usage.

## Example

![image-20240220140659857](https://raw.githubusercontent.com/ayamir/blog-imgs/main/image-20240220140659857.png)

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

### Issues

- Firefox doesn't connect to a server running on localhost. Bind a different interface.
