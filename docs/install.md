# Installation

NSec is available as
[a NuGet package from nuget.org](https://www.nuget.org/packages/NSec.Cryptography/19.1.0-preview1).
It can be added to a project in a number of ways, depending on the project type
and tools used:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 19.1.0-preview1

#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 19.1.0-preview1

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="19.1.0-preview1"/>


## Supported Languages

NSec requires **C# 7.2** or **F# 4.5** (or later).

A C# 7.2 compiler is included with the .NET Core SDK beginning with version 2.1
and Visual Studio beginning with version 15.5.

An F# 4.5 compiler is included with the .NET Core SDK beginning with version
2.1.400 and Visual Studio beginning with version 15.8.


## Supported Platforms

NSec runs on the following platforms and .NET Core versions:

| OS            | Version  | Architectures | .NET Core Runtimes |
|:------------- |:-------- |:------------- |:-------------------|
| Windows 10    | 1803     | x64 / x86     | 2.2 / 2.1          |
|               |          |               |                    |
| macOS         | 10.12    | x64           | 2.2 / 2.1          |
|               |          |               |                    |
| CentOS        | 7.6      | x64           | 2.2 / 2.1          |
| Debian        | 9.8      | x64           | 2.2 / 2.1          |
| Fedora        | 28       | x64           | 2.2 / 2.1          |
|               | 29       | x64           | 2.2                |
| OpenSUSE      | 42.3     | x64           | 2.2 / 2.1          |
| Ubuntu        | 14.04    | x64           | 2.2 / 2.1          |
|               | 16.04    | x64           | 2.2 / 2.1          |
|               | 18.04    | x64           | 2.2 / 2.1          |

Other operating systems and versions supported by .NET Core should work as well
but are not tested.

Using NSec on Windows requires the
[Visual C++ 2015 Redistributable](https://www.microsoft.com/en-us/download/details.aspx?id=53587).
This dependency is automatically installed by the .NET Core installer but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in NSec is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsSupported` property of the
`NSec.Cryptography.Aes256Gcm` class.


### .NET Framework

Running NSec on recent versions of .NET Framework might work as well but is not
tested. It seems that at least the following conditions need to be met:
First, the project needs to use
[*<PackageReference>* package references](https://blog.nuget.org/20170316/NuGet-now-fully-integrated-into-MSBuild.html#what-about-other-project-types-that-are-not-net-core);
projects using *Packages.config* don't work.
Second, the project needs to have the
[Platform Target](https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-page-project-designer-csharp?view=vs-2017#configuration-and-platform)
set to **x64** or **x86**; other platform targets -- including *Any CPU* --
don't work.
