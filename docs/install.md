# Installation

NSec is available as [a NuGet package from
nuget.org](https://www.nuget.org/packages/NSec.Cryptography/18.4.0-preview2). It
can be added to a project in a number of ways, depending on the project type and
tools used:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 18.4.0-preview2


#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 18.4.0-preview2

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="18.4.0-preview2"/>

!!! Note
    This is a pre-release version of NSec.
    Expect some (minor) breaking changes until the release.


## Supported Languages

NSec requires **C# 7.2** or later.

A C# 7.2 compiler is included in the .NET Core SDK beginning with version 2.1
and Visual Studio beginning with version 15.5.
Projects need to opt into C# 7.2 by setting the [Language
Version](https://docs.microsoft.com/en-us/visualstudio/ide/reference/advanced-build-settings-dialog-box-csharp)
to **latest** or **7.2** (or later).


## Supported Platforms

NSec runs on the following platforms and .NET Core versions:

| OS            | Version  | Architectures | .NET Core Runtimes    |
|:------------- |:-------- |:------------- |:--------------------- |
| Windows 10    | 1709     | x64 / x86     | 2.1.0 / 2.0.6 / 1.1.7 |
|               |          |               |                       |
| macOS         | 10.12    | x64           | 2.1.0 / 2.0.6 / 1.1.7 |
|               |          |               |                       |
| CentOS        | 7.4      | x64           | 2.1.0 / 2.0.6 / 1.1.7 |
| Debian        | 8.10     | x64           | 2.1.0 / 2.0.6 / 1.1.7 |
|               | 9.3      | x64           | 2.1.0 / 2.0.6         |
| Fedora        | 26       | x64           | 2.1.0 / 2.0.6         |
|               | 27       | x64           | 2.1.0 / 2.0.6         |
| OpenSUSE      | 42.3     | x64           | 2.1.0 / 2.0.6         |
| Ubuntu        | 14.04    | x64           | 2.1.0 / 2.0.6 / 1.1.7 |
|               | 16.04    | x64           | 2.1.0 / 2.0.6 / 1.1.7 |
|               | 17.10    | x64           | 2.1.0 / 2.0.6         |

Additional operating systems and versions supported by .NET Core should work as
well but are untested.

Using NSec on Windows requires the [Visual C++ 2015
Redistributable](https://www.microsoft.com/en-us/download/details.aspx?id=53587).
This dependency is automatically installed by the .NET Core installer but may
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in NSec is hardware-accelerated and requires a
processor with the Intel SSSE3, AES-NI, and CLMUL extensions. The availability
of these extensions can be checked at runtime using the static `IsSupported`
property of the `NSec.Cryptography.Aes256Gcm` class.


### .NET Framework

Running NSec on recent versions of .NET Framework might work as well but is
untested. It seems at least the following conditions must be met: First, the
project needs to use [*<PackageReference>* package
references](https://blog.nuget.org/20170316/NuGet-now-fully-integrated-into-MSBuild.html#what-about-other-project-types-that-are-not-net-core);
*Packages.config* projects don't work. Second, the project needs to have the
[Platform
Target](https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-page-project-designer-csharp)
set to **x64** or **x86**; other platform targets -- including *Any CPU* --
don't work.
