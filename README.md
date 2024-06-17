# libxom OpenSSL Provider Library

This repository contains implementations of AES and HMAC that make use of libxom's key protection capabilities.
See OpenSSL's documentation on [provider libraries](https://www.openssl.org/docs/man3.0/man7/crypto.html#OPENSSL-PROVIDERS) and [configuration files](https://www.openssl.org/docs/man3.0/man5/config.html) for instructions on how to use them in your project.

Currently, the following algorithms are supported:

 * AES-128-CTR
 * AES-128-GCM
 * HMAC-SHA256 (requires SHA instruction set extensions)

IMPORTANT: This library re-exports all algorithms implemented by the default provider in order to make using it for more involved protocols like TLS easier.
ONLY THE ALGORITHMS LISTED ABOVE UTILIZE XOM. Any other algorithm provided by this library is simply a re-export of OpenSSL's default algorithms.
Furthermore, the HMAC implementation is only exported if you have the AVX2 and SHA instruction set extensions.
Run `lscpu | grep sha` to check whether your CPU supports them. 

### Building

Use cmake to build this project. Besides a working C compiler, you will also need OpenSSL's library headers, which you can install with 
```shell
apt install libssl-dev
```
on Debian-based Linux distros.
To additionally build the demo application, specify ```-DDEMO=1``` when configuring the project.

### Demo Application
This repository comes with a demo application, which utilizes the AES-128-GCM implementation to fetch files from an HTTPS server.
You can run it with 
```shell
./demo_https <your_url>
```

### Acknowledgements
The GCM-Hash implementation in ```provider/src/ghash.s``` was taken from [OpenSSL](https://github.com/openssl/openssl/blob/master/crypto/modes/asm/ghash-x86_64.pl). See the comments for a list of changes that were made to integrate it into this project.
