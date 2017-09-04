# NSec

NSec is a modern and easy-to-use crypto library for
[.NET Core](https://dotnet.github.io/) based on
[libsodium](https://libsodium.org/).

* **Modern** -- libsodium provides a small set of high-quality, modern
cryptographic primitives, including X25519, Ed25519 and ChaCha20-Poly1305. NSec
wraps these primitives in a modern .NET API based on the new `Span<T>` and
`ReadOnlySpan<T>` types.

* **Easy-to-use** -- NSec wants you to fall into the "pit of success." It
provides a strongly typed data model that represents keys and shared secrets
with specific classes rather than naked byte arrays. This avoids, for example,
accidentally using a key with a wrong algorithm. There are still some hard
problems that NSec does not solve, though, such as nonce generation and key
management.

* **Secure** -- In addition to the security provided by the cryptographic
primitives, NSec tries to make the use of these primitives secure by default.
For example, all sensitive data such as keys is stored in libsodium's secure
memory rather than on the managed heap and is securely erased when no longer
needed.

* **Fast** -- libsodium is fast, and cryptographic operations in libsodium never
allocate memory on the heap. NSec follows libsodium's lead and avoids
allocations and expensive copies in almost all cases. Only methods that return
byte arrays, keys or shared secrets do allocate memory and should therefore be
kept off hot paths.

* **Agile** -- NSec features a simple object model with cryptographic agility in
mind. All algorithms derive from a small set of base classes. This helps writing
code against algorithm interfaces rather than specific algorithms, making it
easy to support multiple algorithms or switch algorithms should the need arise.


## Example

The following C# example shows how to use NSec to sign data with Ed25519 and
verify the signature.

    {{README Example}}


## Installation

Soon&trade; (waiting for .NET Core 2.1)


## Documentation

### API Reference

* [[Algorithm Class]]
    * [[AeadAlgorithm Class]]
    * [[HashAlgorithm Class]]
    * [[KeyAgreementAlgorithm Class]]
    * [[KeyDerivationAlgorithm Class]]
    * [[MacAlgorithm Class]]
    * [[SignatureAlgorithm Class]]
* [[Key Class]]
    * [[KeyBlobFormat Enum]]
    * [[KeyFlags Enum]]
* [[PublicKey Class]]
* [[RandomNumberGenerator Class]]
* [[SharedSecret Class]]


## Contributing

NSec is an open source project.
Contributions to the code or documentation are highly welcome.

Development of NSec takes place on its 
[GitHub repository](https://github.com/ektrah/nsec).
The easiest way to contribute is by
[submitting a pull request](https://github.com/ektrah/nsec/pulls).
If you've found an problem with NSec, please
[open a new issue](https://github.com/ektrah/nsec/issues).
Feature requests are welcome, too.


## Note

*"Cryptography is not magic pixie dust that you can sprinkle on a system to make
it secure."*

NSec aims to provide careful abstractions to make the work with modern
cryptographic primitives relatively easy and pain-free. However, the primitives
are not very useful by themselves and need to be combined into higher-level
security protocols, such as TLS. Don't roll your own security protocols.


## License

NSec is licensed under the [[MIT license|License]].
The NSec documentation is licensed under [[a Creative Commons license|License]].
