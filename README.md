# octopine

A network proxy for improved privacy and security

## Feature

`C` for client      `S` for server

### Transport

| Local-Peer | Client-Server | Shadowsocks | VMess | Trojan |
|:----------:|:-------------:|:-----------:|:-----:|:------:|
|   `tcp`    |     `tcp`     |     `S`     |  `S`  |  `S*`  |
|   `tcp`    |     `tls`     |     `S`     |  `S`  |  `S`   |
|   `tcp`    |     `ws`      |     `S`     |  `S`  |  `S*`  |
|   `tcp`    |     `wss`     |     `S`     |  `S`  |  `S`   |
|   `tcp`    |    `quic`     |     `S`     |  `S`  |  `S`   |
|   `udp`    |     `udp`     |    `S**`    |       |        |
|   `udp`    |     `tcp`     |     `S`     |  `S`  |  `S`   |
|   `udp`    |     `tls`     |     `S`     |  `S`  |  `S`   |
|   `udp`    |     `ws`      |     `S`     |  `S`  |  `S`   |
|   `udp`    |     `wss`     |     `S`     |  `S`  |  `S`   |
|   `ucp`    |    `quic`     |    `S**`    |  `S`  |  `S`   |

`*` insecure

`**` prefer using quic; udp will become invalid

### Ciphers

|                               | Shadowsocks | VMess |
|:------------------------------|:-----------:|:-----:|
| aes-128-gcm                   |     `S`     |  `S`  |
| aes-256-gcm                   |     `S`     |       |
| chacha20-poly1305             |     `S`     |  `S`  |
| 2022-blake3-aes-128-gcm       |     `S`     |       |
| 2022-blake3-aes-256-gcm       |     `S`     |       |
| 2022-blake3-chacha8-poly1305  |     `S`     |       |
| 2022-blake3-chacha20-poly1305 |     `S`     |       |

## Architecture

```text
Server.Transport -> Server.Protocol -> Common.Codec.<protocol> -> Common.Protocol.<protocol> -> Common.Crypto
```

```text
src/
  Common/
    Crypto/                 Cipher primitives and nonce state
    Network/                Address model and DNS lookup
    Protocol/               Shadowsocks, VMess, Trojan, and SOCKS rules
    Codec/                  Shared framing and per-protocol byte codecs
  Server/
    Protocol/               ServerConfig adapters, server codecs, and relay commands
    Transport/              TCP, UDP, TLS, WebSocket, and QUIC relay code
```

## Build

build to `/target`

```bash
stack install --local-bin-path target/
```
