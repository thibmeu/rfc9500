<!-- markdownlint-disable MD013 -->
# Public Key Cryptography Test Keys

![GitHub License](https://img.shields.io/github/license/thibmeu/rfc9500)

[RFC 9500](https://www.rfc-editor.org/rfc/rfc9500.html) proposes a set of standard test keys. This repository presents the private and public keys, in different format to ease consumptions.

## Table of Content

* [RSA Keys](#rsa-keys)
* [DLP Keys](#dlp-keys)
* [ECDLP Keys](#ecdlp-keys)
* [Security Considerations](#security-considerations)
* [FAQ](#faq)
* [Development](#development)

## RSA Keys

|testRSA1024|||
|--|--|--|
|private|[pem](./pem/testRSA1024.pem)|[jwk](./jwk/testRSA1024.json)|
|public|[pem](./pem/testRSA1024.pub.pem)|[jwk](./jwk/testRSA1024.pub.json)|

|testRSA2048|||
|--|--|--|
|private|[pem](./pem/testRSA2048.pem)|[jwk](./jwk/testRSA2048.json)|
|public|[pem](./pem/testRSA2048.pub.pem)|[jwk](./jwk/testRSA2048.pub.json)|

|testRSA4096|||
|--|--|--|
|private|[pem](./pem/testRSA4096.pem)|[jwk](./jwk/testRSA4096.json)|
|public|[pem](./pem/testRSA4096.pub.pem)|[jwk](./jwk/testRSA4096.pub.json)|

## DLP Keys

|testDLP1024|||
|--|--|--|
|private|[pem](./pem/testDLP1024.pem)|[hex](./hex/testDLP1024.hex)|
|public|[pem](./pem/testDLP1024.pub.pem)|[hex](./hex/testDLP1024.pub.hex)|

|testDLP2048|||
|--|--|--|
|private|[pem](./pem/testDLP2048.pem)|[hex](./hex/testDLP2048.hex)|
|public|[pem](./pem/testDLP2048.pub.pem)|[hex](./hex/testDLP2048.pub.hex)|

|testDLP4096|||
|--|--|--|
|private|[pem](./pem/testDLP4096.pem)|[hex](./hex/testDLP4096.hex)|
|public|[pem](./pem/testDLP4096.pub.pem)|[hex](./hex/testDLP4096.pub.hex)|

## ECDLP Keys

|testECCP256||||
|--|--|--|--|
|private|[pem](./pem/testECCP256.pem)|[hex](./hex/testECCP256.hex)|[jwk](./jwk/testECCP256.json)|
|public|[pem](./pem/testECCP256.pub.pem)|[hex](./hex/testECCP256.pub.hex)|[jwk](./jwk/testECCP256.pub.json)|

|testECCP384||||
|--|--|--|--|
|private|[pem](./pem/testECCP384.pem)|[hex](./hex/testECCP384.hex)|[jwk](./jwk/testECCP384.json)|
|public|[pem](./pem/testECCP384.pub.pem)|[hex](./hex/testECCP384.pub.hex)|[jwk](./jwk/testECCP384.pub.json)|

|testECCP521||||
|--|--|--|--|
|private|[pem](./pem/testECCP521.pem)|[hex](./hex/testECCP521.hex)|[jwk](./jwk/testECCP521.json)|
|public|[pem](./pem/testECCP521.pub.pem)|[hex](./hex/testECCP521.pub.hex)|[jwk](./jwk/testECCP521.pub.json)|

## Security considerations

This software has not been audited. Please use at your sole discretion. With this in mind, dee security relies on the following:

* [RFC 9500](https://www.rfc-editor.org/rfc/rfc9500.html) holds the source cryptographic material, and more.

## FAQ

### Should I use this in production

**NO**. At the same time, this repository might allow you to detect such usages.

### How do I get a test certificate

For local development, have a look at [mkcert](https://github.com/FiloSottile/mkcert).
If you want to generate a fresh certificate with one of the RFC provided test key, use the following

```bash
# Select a PEM formated key in this repository
KEY=./pem/testRSA1024.pem
# Generate a Certificate Signing Request
openssl req -new -key "${KEY}"  -out example_test.csr
# Generate the associated certificate
openssl x509 -req -in example_test.csr -signkey ./pem/testRSA1024.pem -out example_test.crt
```

## Development

### Requirements

* [bash](https://www.gnu.org/software/bash/)
* [OpenSSL](https://www.openssl.org/)

### Run

All development happens in [generate.sh](./scripts/generate.sh). The initial private key in PEM format have been taken from RFC 9500, along with their recommended name. The script has then been run to generate public keys, and hex encoded keys.

```bash
./scripts/generate.sh
```
