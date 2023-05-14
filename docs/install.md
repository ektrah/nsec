# Installation

NSec is available as
[a NuGet package from nuget.org](https://www.nuget.org/packages/NSec.Cryptography/23.5.0-preview.1).
It can be added to a project in a number of ways, depending on the project type
and tools used:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 23.5.0-preview.1

#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 23.5.0-preview.1

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="23.5.0-preview.1"/>


## Supported Platforms

NSec is intended to run on
[supported versions of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
on the following platforms:

|                       | `-x64`   | `-x86`   | `-arm64` | `-arm`   |
|:----------------------|:--------:|:--------:|:--------:|:--------:|
| **`win-`**            | &check;  | &check;  |          |          |
| **`linux-`**          | &check;  |          | &check;  | &check;  |
| **`linux-musl-`**     | &check;  |          | &check;  | &check;  |
| **`osx-`**            | &check;  |          | &check;  |          |
| **`ios-`**            |          |          |          |          |
| **`android-`**        |          |          |          |          |

Specifically,
[NSec 23.5.0-preview.1](https://www.nuget.org/packages/NSec.Cryptography/23.5.0-preview.1)
has been tested to run on the following platforms and .NET versions:

| OS                   | Version  | Architectures | .NET            |
|:-------------------- |:-------- |:------------- |:--------------- |
| Windows 11           | 22H2     | x64           | 7.0.5 / 6.0.16  |
| Windows Server       | 2022     | x64           | 7.0.5 / 6.0.16  |
|                      |          |               |                 |
| macOS                | 11.7     | x64           | 7.0.5 / 6.0.16  |
|                      | 12.6     | x64           | 7.0.5 / 6.0.16  |
|                      | 13.3     | x64           | 7.0.5 / 6.0.16  |
|                      |          |               |                 |
| Alpine               | 3.17     | x64           | 7.0.4           |
| CentOS               | 7.9.2009 | x64           | 7.0.5 / 6.0.16  |
| Debian               | 10.13    | x64           | 7.0.5 / 6.0.16  |
|                      | 11.7     | x64           | 7.0.5 / 6.0.16  |
| Fedora               | 37       | x64           | 7.0.5 / 6.0.16  |
|                      | 38       | x64           | 7.0.5 / 6.0.16  |
| Ubuntu               | 16.04    | x64           | 7.0.5 / 6.0.16  |
|                      | 18.04    | x64           | 7.0.5 / 6.0.16  |
|                      | 20.04    | x64           | 7.0.5 / 6.0.16  |
|                      | 22.04    | x64           | 7.0.5 / 6.0.16  |

Other, similar platforms supported by .NET should work as well but have not been tested.

Using NSec on Windows requires the
[Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).
This dependency is included in the .NET SDK but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in NSec is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsSupported` property of the
`NSec.Cryptography.Aes256Gcm` class.
