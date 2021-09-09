# NSec

NSec is a modern and easy-to-use cryptographic library for
[.NET 5.0](https://dotnet.microsoft.com/) and
[.NET Core](https://dotnet.microsoft.com/) based on
[libsodium](https://libsodium.org/).

* **Modern** -- libsodium provides a small set of high-quality, modern
cryptographic primitives, including X25519, Ed25519 and ChaCha20-Poly1305. NSec
wraps these primitives in a modern .NET API based on [Span<T>](https://docs.microsoft.com/en-us/archive/msdn-magazine/2017/connect/csharp-all-about-span-exploring-a-new-net-mainstay).

* **Easy-to-use** -- NSec wants you to fall into the "pit of success." It
provides a strongly typed data model that represents keys and shared secrets
with specific classes rather than naked byte arrays. This avoids accidentally
using a key with a wrong algorithm, etc. (There are still some hard problems
where NSec isn't as easy-to-use as one might wish, though, such as nonce
generation and key management.)

* **Secure** -- In addition to the security provided by the cryptographic
primitives themselves, NSec tries to make using these primitives as secure by
default as possible. For example, all sensitive data such as keys is stored in
libsodium's secure memory rather than on the managed heap and is securely erased
when disposed.

* **Fast** -- libsodium is fast, and cryptographic operations in libsodium never
allocate memory on the heap. NSec follows libsodium's lead and avoids almost all
allocations and expensive copies. Only methods that return byte arrays, keys or
shared secrets do allocate memory and should therefore be avoided in hot paths.

* **Agile** -- NSec features a simple object model with cryptographic agility in
mind. All algorithms derive from a small set of base classes. This helps writing
code against algorithm interfaces rather than specific algorithms, making it
easy to switch to a different algorithm should the need arise.


## Example

The following C# example shows NSec can be used to sign some data with Ed25519
and verify the signature:

    {{Teaser}}


## Installation

    $ dotnet add package NSec.Cryptography --version 20.11.0-preview1

NSec works with .NET 5.0 and .NET Core 3.1 on Windows, Linux and macOS.

See [[Installation]] for more information.


## Documentation

| Class                                           | Algorithms                |
|:----------------------------------------------- |:------------------------- |
| [[AeadAlgorithm Class]]                         | AES256-GCM                |
|                                                 | ChaCha20-Poly1305         |
| [[HashAlgorithm Class]]                         | BLAKE2b *(unkeyed)*       |
|                                                 | SHA-256                   |
|                                                 | SHA-512                   |
| [[KeyAgreementAlgorithm Class]]                 | X25519                    |
| [[KeyDerivationAlgorithm Class]]                | HKDF-SHA-256              |
|                                                 | HKDF-SHA-512              |
| [[MacAlgorithm Class]]                          | BLAKE2b *(keyed)*         |
|                                                 | HMAC-SHA-256              |
|                                                 | HMAC-SHA-512              |
| [[PasswordBasedKeyDerivationAlgorithm Class]]   | Argon2id                  |
|                                                 | scrypt                    |
| [[SignatureAlgorithm Class]]                    | Ed25519                   |

See [[API Reference|NSec.Cryptography Namespace]] for more information.


## Contributing

NSec is an open source project.
Contributions to the code or documentation are highly welcome.

The development of NSec takes place in its
[GitHub repository](https://github.com/ektrah/nsec).
The easiest way to contribute is by
[submitting a pull request](https://github.com/ektrah/nsec/pulls).
Please ask before making a significant pull request (e.g., implementing any new
features).
If you've found a problem with NSec, please
[open an issue](https://github.com/ektrah/nsec/issues).
Feature requests and questions are welcome, too.


## Note

*"Cryptography is not magic pixie dust that you can sprinkle on a system to make
it secure."*

NSec aims to provide careful abstractions to make the work with modern
cryptographic primitives relatively easy and pain-free. However, the primitives
are not very useful by themselves and need to be combined into higher-level
security protocols (such as TLS or CBOR Web Token). Don't roll your own security
protocols.


## License

NSec is licensed under the [[MIT license|License]].
