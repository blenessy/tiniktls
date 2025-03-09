# What is tiniktls ?

tl;dr: It is a fork of [tini][1] with support for [ktls][2] socket management.

`tini` is a popular init program (pid 1), commonly used in docker containers for its small size.
It handles [process reaping][4] on behalf of it's child process.

`tiniktls` introduces a control socket and a simple text based protocol,
through which the child process:

1. request TLS connection to remote hosts (client)
2. request listening for incoming TLS connections (server)

`tiniktls` responds with the file-descriptor to fully-negotiated KTLS sockets.
The child process can bind the file descriptor to a socket and use that directly with
unencrypted data knowing that the Kernel handles the encryption/decryption transparently. 

This effectively means that the TLS stack (which is usually a big part of the child application)
 is moved into `tiniktls` (handshake) and kernel (encryption/decryption).

The primary benefits are:

* Smaller child applications
* Faster TLS data path as encryption/decryptions is done by the Kernel

## TLS 1.2 support

Given that you are using [Linux 5.11 with the tls module loaded][2], the following OpenSSL Cipher List is supported:

* `ECDHE-ECDSA-AES128-GCM-SHA256`
* `ECDHE-RSA-AES128-GCM-SHA256`
* `ECDHE-ECDSA-AES256-GCM-SHA384`
* `ECDHE-RSA-AES256-GCM-SHA384`
* `ECDHE-ECDSA-CHACHA20-POLY1305`
* `ECDHE-RSA-CHACHA20-POLY1305`

## TLS 1.3 support

Given that you are using [Linux 5.11 with the tls module loaded][2], the following OpenSSL Cipher Suite is supported:

* `TLS_AES_128_GCM_SHA256`
* `TLS_AES_256_GCM_SHA384`
* `TLS_CHACHA20_POLY1305_SHA256`

# Development

The following tools needs to be installed before you begin:

* `docker`


## Building tiniktls

The `tiniktls-builder` Docker image contains the [musl toolchain][5] and custom built OpenSSL for `tiniktls`.
You can build it with docker:

```shell
docker build -t tiniktls-builder -f docker/Dockerfile.builder docker
```

During development build `tiniktls` and update `SHA256SUMS` with:

```shell
docker run --rm -it -v "$PWD:/tiniktls" -e SHA256SUMS=update tiniktls-builder
```

If you want to build `tiniktls` and check that it matches the hash in `SHA256SUMS`:

```shell
docker run --rm -it -v "$PWD:/tiniktls" tiniktls-builder
```

## Testing tiniktls

Build the `tiniktls-qa` Docker image, which incorporates the test environment for tiniktls:

```shell
docker build -t tiniktls-qa -f docker/Dockerfile.qa docker
```

Run the tests and other QA checks with:

```shell
docker run --rm -it -v "$PWD:/tiniktls" tiniktls-qa
```

# Goals

The goal of this project is to provide a secure and performant TLS solution for child applications,
which do not want to bother with their own TLS stack.

1. Security: only safe TLS 1.2/1.3 ciphers are included
1. Auditability: small well written code base that can be easily scrutinized by auditors 
1. Reproducibility: build twice on different environments and get bit-exact binaries
1. Performance: it should be possible to implement i.e. a performant TLS reverse proxies with `tiniktls` in front.

# Contribution

* TLS improving features are generally welcome as long it does not degrade any of the [goals](#goals) significantly.
* Transport related features like rate-limiting/load-balancing might be welcome if code size is small - talk to me first!

[1]: https://github.com/krallin/tini
[2]: https://delthas.fr/blog/2023/kernel-tls/
[3]: https://www.openssl.org/
[4]: https://en.wikipedia.org/wiki/Zombie_process
[5]: https://www.musl-libc.org/

