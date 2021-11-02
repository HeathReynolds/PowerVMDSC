# PowerVMDSC

There are known issues with Windows 2012r2 (using either Powershell Core or Powershell Desktop). VMDSC requires TLS 1.2 or 1.3 with a secure cipher set, the cipher sets supported by the Windows 2012r2 TLS 1.2 implementation are not compatible with VMDSC. Please use a more modern windows operating system supporting the following cipher sets :

Preferred TLSv1.3 128 bits TLS_AES_128_GCM_SHA256 Curve 25519 DHE 253

Accepted TLSv1.3 256 bits TLS_CHACHA20_POLY1305_SHA256 Curve 25519 DHE 253

Accepted TLSv1.3 256 bits TLS_AES_256_GCM_SHA384 Curve 25519 DHE 253

Preferred TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256 Curve 25519 DHE 253

Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-GCM-SHA384 Curve 25519 DHE 253
