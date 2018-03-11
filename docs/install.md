# Installation

NSec is available as [a NuGet package from
nuget.org](https://www.nuget.org/packages/NSec.Cryptography/18.2.0-preview1). It
can be added to a project in a number of ways, depending on the project type and
available tools:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 18.2.0-preview1


#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 18.2.0-preview1

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="18.2.0-preview1"/>

!!! Note
    This is a pre-release version of NSec.
    Expect some (minor) breaking changes until the release.


## Supported Languages

Using NSec requires **C# 7.2** or later. A C# 7.2 compiler is included in the
.NET Core SDK beginning with version 2.1 and in Visual Studio beginning with
version 15.5.

Projects using NSec need to opt into C# 7.2 by setting the [Language
Version](https://docs.microsoft.com/en-us/visualstudio/ide/reference/advanced-build-settings-dialog-box-csharp)
to **latest** or **7.2** (or later).


## Supported Platforms

Running NSec is supported on the following platforms and .NET Core versions:

| OS            | Version  | Architectures | .NET Core Runtimes    |
|:------------- |:-------- |:------------- |:--------------------- |
| Windows 10    | 1709     | x64 / x86     | 2.1.0 / 2.0.5 / 1.1.6 |
|               |          |               |                       |
| macOS         | 10.12    | x64           | 2.1.0 / 2.0.5 / 1.1.6 |
|               |          |               |                       |
| CentOS        | 7.4      | x64           | 2.1.0 / 2.0.5 / 1.1.6 |
| Debian        | 8.10     | x64           | 2.1.0 / 2.0.5 / 1.1.6 |
|               | 9.3      | x64           | 2.1.0 / 2.0.5         |
| Fedora        | 26       | x64           | 2.1.0 / 2.0.5         |
|               | 27       | x64           | 2.1.0 / 2.0.5         |
| OpenSUSE      | 42.3     | x64           | 2.1.0 / 2.0.5         |
| Ubuntu        | 14.04    | x64           | 2.1.0 / 2.0.5 / 1.1.6 |
|               | 16.04    | x64           | 2.1.0 / 2.0.5 / 1.1.6 |
|               | 17.10    | x64           | 2.1.0 / 2.0.5         |

Additional operating systems and versions should work as well but are untested.

Using NSec on Windows requires the [Visual C++ 2015
Redistributable](https://www.microsoft.com/en-us/download/details.aspx?id=53587).
This dependency is automatically installed by the .NET Core installer but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in NSec is hardware-accelerated and requires a
processor with the Intel SSSE3, AES-NI, and CLMUL extensions. The availability
of these extensions can be checked at runtime using the static `IsSupported`
property of the `NSec.Cryptography.Aes256Gcm` class.
