FROM alpine:3.21

RUN apk --no-cache add musl-dev gcc make perl linux-headers cmake curl

COPY musl.cmake /opt/musl.cmake
ENV CMAKE_TOOLCHAIN_FILE=/opt/musl.cmake

# download and build openssl
WORKDIR /opt/openssl
RUN curl -fsL --tlsv1.3 https://github.com/openssl/openssl/archive/refs/tags/openssl-3.3.2.tar.gz -o openssl.tgz && \
    test "$(sha256sum <openssl.tgz)" = 'bedbb16955555f99b1a7b1ba90fc97879eb41025081be359ecd6a9fcbdf1c8d2  -' && \
    tar -xzf openssl.tgz --strip-components 1 && \
    rm openssl.tgz

# NOTE: no-asm makes it a lot smaller but also a lot slower (no free lunch)
RUN ./Configure enable-ktls no-docs no-tests no-shared no-afalgeng no-async no-capieng no-cmp no-cms \
    no-comp no-ct no-dgram no-dso no-dynamic-engine no-engine no-filenames no-gost no-http no-legacy \
    no-module no-nextprotoneg no-ocsp no-padlockeng no-quic no-srp no-srtp no-ssl-trace no-thread-pool \
    no-ts no-ui-console no-uplink no-ssl3-method no-tls1-method no-tls1_1-method no-dtls1-method \
    no-dtls1_2-method no-argon2 no-bf no-blake2 no-cast no-cmac no-dsa no-idea no-md4 no-mdc2 no-ocb no-rc2 \
    no-rc4 no-rmd160 no-scrypt no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool no-threads no-deprecated \
    no-des no-atexit no-psk no-pinshared no-autoerrinit no-autoload-config no-camellia \
    no-seed no-ec2m no-ecx no-sm2-precomp no-cached-fetch no-aria no-sse2 no-asm \
    CC=x86_64-alpine-linux-musl-gcc \
    CFLAGS="-Os -static -fdata-sections -ffunction-sections -flto=auto" \
    LDFLAGS="-static -Wl,--gc-sections"    
RUN make -j$(nproc) && make install

ADD build.sh /opt/

WORKDIR /tiniktls

CMD ["/opt/build.sh"]

