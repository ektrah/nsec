# NSec.Cryptography

NSec is a cryptographic library for .NET based on libsodium. It aims to be easy to use, secure by default, fast, and agile.

## Getting Started

To get started with NSec, install the package via NuGet:

```
dotnet add package NSec.Cryptography
```

For more detailed documentation, usage examples, and API references, please visit [the project homepage](https://nsec.rocks/).

## Documentation

| Class                                                                                                                             | Algorithms                |
|:--------------------------------------------------------------------------------------------------------------------------------- |:------------------------- |
| [AeadAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.aeadalgorithm)                                                | AEGIS-128L                |
|                                                                                                                                   | AEGIS-256                 |
|                                                                                                                                   | AES256-GCM                |
|                                                                                                                                   | ChaCha20-Poly1305         |
|                                                                                                                                   | XChaCha20-Poly1305        |
| [HashAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.hashalgorithm)                                                | BLAKE2b *(unkeyed)*       |
|                                                                                                                                   | SHA-256                   |
|                                                                                                                                   | SHA-512                   |
| [KeyAgreementAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.keyagreementalgorithm)                                | X25519                    |
| [KeyDerivationAlgorithm2 Class](https://nsec.rocks/docs/api/nsec.cryptography.keyderivationalgorithm2)                            | HKDF-SHA-256              |
|                                                                                                                                   | HKDF-SHA-512              |
| [MacAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.macalgorithm)                                                  | BLAKE2b *(keyed)*         |
|                                                                                                                                   | HMAC-SHA-256              |
|                                                                                                                                   | HMAC-SHA-512              |
| [PasswordBasedKeyDerivationAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.passwordbasedkeyderivationalgorithm)    | Argon2id                  |
|                                                                                                                                   | scrypt                    |
| [SignatureAlgorithm Class](https://nsec.rocks/docs/api/nsec.cryptography.signaturealgorithm)                                      | Ed25519                   |
| [SignatureAlgorithm2 Class](https://nsec.rocks/docs/api/nsec.cryptography.signaturealgorithm2)                                    | Ed25519ph                 |

See [the API reference](https://nsec.rocks/docs/api/nsec.cryptography) for more information.

## Supported Platforms

NSec is intended to run on the following platforms. Please note, not all of these platforms have been tested.

|                       | `-x64`   | `-x86`   | `-arm64` | `-arm`   |
|:----------------------|:--------:|:--------:|:--------:|:--------:|
| **`android-`**        |          |          |          |          |
| **`ios-`**            |          |          | &check;  |          |
| **`linux-`**          | &check;  |          | &check;  | &check;  |
| **`linux-musl-`**     | &check;  |          | &check;  | &check;  |
| **`maccatalyst-`**    | &check;  |          | &check;  |          |
| **`osx-`**            | &check;  |          | &check;  |          |
| **`tvos-`**           |          |          | &check;  |          |
| **`win-`**            | &check;  | &check;  | &check;  |          |

See [the installation instructions](https://nsec.rocks/docs/install) for more information, particularly regarding hardware and software requirements.
