# Installation

Use the following command to install the
[NSec.Cryptography NuGet package](https://www.nuget.org/packages/NSec.Cryptography/25.2.0-preview.3):

    $ dotnet add package NSec.Cryptography --version 25.2.0-preview.3


## Supported Platforms

[NSec 25.2.0-preview.3](https://www.nuget.org/packages/NSec.Cryptography/25.2.0-preview.3)
is intended to run on all
[supported versions of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
on the following platforms:

|                       | `-x64`   | `-x86`   | `-arm64` | `-arm`   |
|:----------------------|:--------:|:--------:|:--------:|:--------:|
| **`android-`**        |          |          |          |          |
| **`ios-`**            |          |          | &check;  |          |
| **`linux-`**          | &check;  |          | &check;  | &check;  |
| **`linux-musl-`**     | &check;  |          | &check;  | &check;  |
| **`maccatalyst-`**    | &check;  |          | &check;  |          |
| **`osx-`**            | &check;  |          | &check;  |          |
| **`tvos-`**           |          |          | &check;  |          |
| **`win-`**            | &check;  | &check;  | &check;  |          |


Please note:

1. For Windows, the
   [Microsoft Visual C++ Redistributable for Visual Studio 2015, 2017, 2019, and 2022](https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist)
   is required. This is part of the .NET SDK but might not be present on a
   clean Windows installation.

2. The AES-GCM implementation in NSec is hardware-accelerated and may not be
   available on all architectures. Support can be determined at runtime using
   the static `IsSupported` property of the `NSec.Cryptography.Aes256Gcm` class.


## Tested Platforms

[NSec 25.2.0-preview.3](https://www.nuget.org/packages/NSec.Cryptography/25.2.0-preview.3)
has been tested to run on the following platforms and .NET versions:

| OS                   | Version  | Architecture  | .NET   |
|:-------------------- |:-------- |:------------- |:-------|
| Windows 11           | 23H2     | x64           | 8.0.11 |
| Windows Server 2022  | LTSC     | x64           | 8.0.11 |
|                      |          |               |        |
| macOS                | 13.7     | x64           | 8.0.11 |
|                      | 14.7     | arm64         | 8.0.11 |
|                      | 15.1     | arm64         | 8.0.11 |
|                      |          |               |        |
| Alpine Linux         | 3.18     | x64           | 8.0.6  |
|                      | 3.19     | x64           | 8.0.8  |
|                      | 3.20     | x64           | 8.0.11 |
| Debian               | 12       | x64           | 8.0.11 |
| Fedora               | 40       | x64           | 8.0.11 |
| Ubuntu               | 20.04    | x64           | 8.0.11 |
|                      | 22.04    | x64           | 8.0.11 |
|                      | 24.04    | x64           | 8.0.11 |

The other supported platforms should work as well, but have not been tested.


## Frequently Asked Questions

Below are some frequently asked questions:

**Q**: What causes a *System.DllNotFoundException: Unable to load shared
library 'libsodium' or one of its dependencies.* when using the
NSec.Cryptography NuGet package?  
**A**: This exception can occur if the operating system or architecture is not
supported, or if the Visual C++ Redistributable has not been installed on a
Windows system. Please refer to the [Supported Platforms](#supported-platforms)
section above.
