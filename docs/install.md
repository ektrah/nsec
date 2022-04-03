# Installation

NSec is available as
[a NuGet package from nuget.org](https://www.nuget.org/packages/NSec.Cryptography/22.4.0-preview3).
It can be added to a project in a number of ways, depending on the project type
and tools used:


#### dotnet CLI

    $ dotnet add package NSec.Cryptography --version 22.4.0-preview3

#### Visual Studio

    PM> Install-Package NSec.Cryptography -Version 22.4.0-preview3

#### .csproj

    <PackageReference Include="NSec.Cryptography" Version="22.4.0-preview3"/>


## Supported Languages

NSec requires **C# 7.2** or **F# 4.5** (or later).


## Supported Platforms

NSec runs on the following platforms and .NET versions:

| OS                   | Version  | Architectures | .NET          | .NET Core   |
|:-------------------- |:-------- |:------------- |:--------------|:------------|
| Windows 10 Client    | 20H2     | x64, x86      | 6.0, 5.0      | 3.1         |
| Windows Server       | 2022     | x64           | 6.0, 5.0      | 3.1         |
|                      |          |               |               |             |
| macOS                | 10.15.5  | x64           | 6.0, 5.0      | 3.1         |
|                      | 11.6.2   | x64           | 6.0, 5.0      | 3.1         |
|                      | 12.2.1   | x64           | 6.0, 5.0      | 3.1         |
|                      |          |               |               |             |
| Alpine               | 3.14     | x64           | 6.0           | 3.1         |
|                      | 3.15     | x64           | 6.0           |             |
| CentOS               | 7.9.2009 | x64           | 6.0, 5.0      | 3.1         |
| Debian               | 9.13     | x64           | 6.0, 5.0      | 3.1         |
|                      | 10.11    | x64           | 6.0, 5.0      | 3.1         |
|                      | 11.1     | x64           | 6.0, 5.0      | 3.1         |
| Fedora               | 33       | x64           | 6.0, 5.0      | 3.1         |
|                      | 34       | x64           | 6.0, 5.0      | 3.1         |
|                      | 35       | x64           | 6.0, 5.0      | 3.1         |
| OpenSUSE             | 15.2     | x64           | 6.0, 5.0      | 3.1         |
| Ubuntu               | 16.04    | x64           | 6.0, 5.0      | 3.1         |
|                      | 18.04    | x64           | 6.0, 5.0      | 3.1         |
|                      | 20.04    | x64           | 6.0, 5.0      | 3.1         |

Other, similar platforms supported by .NET should work as well but have not been tested.

Using NSec on Windows requires the
[Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads).
This dependency is included in the .NET SDK but might
not be present, for example, when deploying a self-contained application.

The implementation of AES-GCM in NSec is hardware-accelerated and requires an
x64 processor with the AES-NI extension. The availability of this extension can
be determined at runtime using the static `IsSupported` property of the
`NSec.Cryptography.Aes256Gcm` class.
