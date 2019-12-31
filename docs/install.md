# Installation

NSec is available as
[a NuGet package from nuget.org](https://www.nuget.org/packages/NSec.Cryptography/19.12.0-preview1).
It can be added to a project in a number of ways, depending on the project type
and tools used:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 19.12.0-preview1

#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 19.12.0-preview1

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="19.12.0-preview1"/>


## Supported Languages

NSec requires **C# 7.2** or **F# 4.5** (or later).


## Supported Platforms

NSec runs on the following platforms and .NET Core versions:

| OS            | Version  | Architectures | .NET Core Runtimes |
|:------------- |:-------- |:------------- |:-------------------|
| Windows 10    | 1809     | x64 / x86     | 3.1 / 3.0 / 2.1    |
|               |          |               |                    |
| macOS         | 10.13    | x64           | 3.1 / 3.0 / 2.1    |
|               | 10.14    | x64           | 3.1 / 3.0 / 2.1    |
|               | 10.15    | x64           | 3.1 / 3.0 / 2.1    |
|               |          |               |                    |
| CentOS        | 7        | x64           | 3.1 / 3.0 / 2.1    |
|               | 8        | x64           | 3.1 / 3.0 / 2.1    |
| Debian        | 9.11     | x64           | 3.1 / 3.0 / 2.1    |
|               | 10.2     | x64           | 3.1 / 3.0          |
| Fedora        | 29       | x64           | 3.1 / 3.0 / 2.1    |
|               | 30       | x64           | 3.1 / 3.0 / 2.1    |
|               | 31       | x64           | 3.1 / 3.0          |
| OpenSUSE      | 15.2     | x64           | 3.1 / 3.0 / 2.1    |
| Ubuntu        | 16.04    | x64           | 3.1 / 3.0 / 2.1    |
|               | 18.04    | x64           | 3.1 / 3.0 / 2.1    |

Other operating systems and versions supported by .NET Core should work as well
but are not tested.

Using NSec on Windows requires the
[Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017 and 2019](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).
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
[*<PackageReference>* package references](https://devblogs.microsoft.com/nuget/NuGet-now-fully-integrated-into-MSBuild/);
projects using *Packages.config* don't work.
Second, the project needs to have the
[Platform Target](https://docs.microsoft.com/en-us/visualstudio/ide/reference/build-page-project-designer-csharp?view=vs-2019#configuration-and-platform)
set to **x64** or **x86**; other platform targets -- including *Any CPU* --
don't work.
