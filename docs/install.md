# Installation

NSec is available as
[a NuGet package from nuget.org](https://www.nuget.org/packages/NSec.Cryptography/22.4.0).
It can be added to a project in a number of ways, depending on the project type
and tools used:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 22.4.0

#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 22.4.0

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="22.4.0"/>


## Supported Platforms

NSec is intended to run on
[supported versions of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
on the following platforms:

* Windows
    * `win-x64`
    * `win-x86`
* Linux
    * `linux-x64` (Most desktop distributions like CentOS, Debian, Fedora, Ubuntu, and derivatives)
    * `linux-musl-x64` (Lightweight distributions using musl like Alpine Linux)
    * `linux-arm` (Linux distributions running on ARM like Raspbian on Raspberry Pi Model 2+)
    * `linux-arm64` (Linux distributions running on 64-bit ARM like Ubuntu Server 64-bit on Raspberry Pi Model 3+)
* macOS
    * `osx-x64`
    * `osx-arm64`

Specifically,
[NSec 22.4.0](https://www.nuget.org/packages/NSec.Cryptography/22.4.0)
has been tested to run on the following platforms and .NET versions:

| OS                   | Version  | Architectures | .NET          |
|:-------------------- |:-------- |:------------- |:--------------|
| Windows 10 Client    | 20H2     | x64 / x86     | 6.0           |
| Windows Server       | 2022     | x64           | 6.0           |
|                      |          |               |               |
| macOS                | 10.15.5  | x64           | 6.0           |
|                      | 11.6.2   | x64           | 6.0           |
|                      | 12.2.1   | x64           | 6.0           |
|                      |          |               |               |
| Alpine               | 3.14     | x64           | 6.0           |
|                      | 3.15     | x64           | 6.0           |
| CentOS               | 7.9.2009 | x64           | 6.0           |
| Debian               | 9.13     | x64           | 6.0           |
|                      | 10.11    | x64           | 6.0           |
|                      | 11.1     | x64           | 6.0           |
| Fedora               | 33       | x64           | 6.0           |
|                      | 34       | x64           | 6.0           |
|                      | 35       | x64           | 6.0           |
| OpenSUSE             | 15.2     | x64           | 6.0           |
| Ubuntu               | 16.04    | x64           | 6.0           |
|                      | 18.04    | x64           | 6.0           |
|                      | 20.04    | x64           | 6.0           |

Other, similar platforms supported by .NET should work as well but have not been tested.

Using NSec on Windows requires the
[Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).
This dependency is included in the .NET SDK but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in NSec is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsSupported` property of the
`NSec.Cryptography.Aes256Gcm` class.
