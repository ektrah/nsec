# Installation

**Note:** NSec depends on .NET Core pre-release features and is therefore not
yet ready for production.

If you're adventurous, you can use use NSec in a .NET Core project as follows:

1. Download and install the [.NET Core SDK 1.0 Preview 4](https://github.com/dotnet/core/blob/master/release-notes/preview4-download.md)
    or the latest [Visual Studio 2017 Release Candidate](https://www.visualstudio.com/vs/visual-studio-2017-rc/).

2. Add the [.NET Core "dev" builds feed](https://dotnet.myget.org/gallery/dotnet-core) as a NuGet package source

3. Add the following package reference to your `.csproj` file:

        <PackageReference Include="NSec.Cryptography" Version="1.0.0-preview-24912-01" />


## Supported Platforms

### Windows

* Windows 10 / Windows Server 2016
    * `win10-x64`
    * `win10-x86`
    
### Linux

* CentOS
    * `centos.7-x64`
* Debian
    * `debian.8-x64`
* Fedora
    * `fedora.23-x64`
    * `fedora.24-x64`
    * `fedora.25-x64`
* OpenSUSE
    * `opensuse.42.1-x64`
    * `opensuse.42.2-x64`
* Red Hat Enterprise Linux
    * `rhel.7-x64`
* Ubuntu
    * `ubuntu.14.04-x64`
    * `ubuntu.16.04-x64`
    * `ubuntu.16.10-x64`
    
### macOS

* Yosemite
    * `osx.10.10-x64`
* El Capitan
    * `osx.10.11-x64`
* Sierra
    * `osx.10.12-x64`



