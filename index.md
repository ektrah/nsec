# NSec

NSec is a modern and easy-to-use crypto library for
[.NET Core](https://dotnet.github.io/) based on
[libsodium](https://libsodium.org/) &#x2764;.

* **Modern** -- libsodium provides a small set of high-quality, modern
cryptographic primitives, including X25519, Ed25519 and ChaCha20-Poly1305. NSec
wraps libsodium in a modern .NET API based on `Span<T>` and `ReadOnlySpan<T>`.

* **Easy-to-use** -- NSec throws you into the "pit of success" by providing a
strongly typed data model. Keys and shared secrets are represented using
specific classes rather than naked byte arrays. This avoids, for example,
accidentally using a key with the wrong algorithm.

* **Secure** -- In addition to the security provided by the cryptographic
primitives, NSec tries to make working with these primitives as secure as
possible. All sensitive data such as keys is stored in libsodium's secure memory
rather than on the managed heap and securely erased when it's no longer needed.

* **Fast** -- libsodium is fast, and cryptographic operations in libsodium never
allocate memory on the heap. NSec follows libsodium's example and avoids
allocations and expensive copies in almost all cases. Only methods that return
byte arrays or create keys do allocate memory and should be kept outside hot
paths.

* **Agile** -- NSec features a simple object model with cryptographic agility in
mind. All algorithms derive from a small set of base classes. This helps writing
code against algorithm interfaces rather than specific implementations, making
it easy to support multiple algorithms or switch algorithms should the need
arise.


## Example

The following C# example shows how to use NSec to sign data with Ed25519 and
verify the signature.

    {{README Example}}

See the [[documentation|NSec Documentation]] for more examples.


## Installation

**Note:** NSec depends on .NET Core pre-release features and is therefore not
yet ready for production.

A pre-release version of NSec is available as a package from
[nuget.org](https://www.nuget.org/packages/nsec.cryptography).

To use NSec in a .NET Core project, add the following package reference to your
`.csproj` file:

    <PackageReference Include="NSec.Cryptography" Version="1.0.0-preview-24912-01" />

See [[Installation]] for more information.


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
* [[SecureRandom Class]]
* [[SharedSecret Class]]


## Contributing

The source code and issues are
[hosted on GitHub](https://github.com/ektrah/nsec).

If you've found an problem in NSec, please
[open a new GitHub issue](https://github.com/ektrah/nsec/issues).
Feature requests are welcome, too.

[Pull requests](https://github.com/ektrah/nsec/pulls) -- patches, improvements,
new features -- are a fantastic help. Please ask first before embarking on any
significant pull request (e.g., implementing new features).


## Caution

*Cryptography is not magic pixie dust that you can sprinkle on a system to make
it secure.*

NSec aims to provide careful abstractions to make the work with modern
cryptographic primitives relatively easy and pain-free. However, the primitives
are not very useful by themselves and need to be combined into higher-level
security schemes, such as TLS or JSON Web Token. Don't roll your own security.


## License

NSec is licensed under the [[MIT license|License]].
This documentation is licensed under [[a Creative Commons license|License]].
