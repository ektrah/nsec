# Installation

Use the following command to install the
[NSec.Cryptography NuGet package](https://www.nuget.org/packages/NSec.Cryptography/24.5.0-preview.1):

    $ dotnet add package NSec.Cryptography --version 24.5.0-preview.1


## Supported Platforms

[NSec 24.5.0-preview.1](https://www.nuget.org/packages/NSec.Cryptography/24.5.0-preview.1)
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

[NSec 24.5.0-preview.1](https://www.nuget.org/packages/NSec.Cryptography/24.5.0-preview.1)
has been tested to run on the following platforms and .NET versions:

| OS                   | Version  | Architecture  | .NET  |
|:-------------------- |:-------- |:------------- |:------|
| Windows 11           | 23H2     | x64           | 8.0.4 |
| Windows Server       | 2022     | x64           | 8.0.4 |
|                      |          |               |       |
| macOS                | 12.7     | x64           | 8.0.4 |
|                      | 13.6     | x64           | 8.0.4 |
|                      | 14.4     | arm64         | 8.0.4 |
|                      |          |               |       |
| Alpine Linux         | 3.18     | x64           | 8.0.4 |
|                      | 3.19     | x64           | 8.0.4 |
| Debian               | 10       | x64           | 8.0.4 |
|                      | 11       | x64           | 8.0.4 |
|                      | 12       | x64           | 8.0.4 |
| Fedora               | 38       | x64           | 8.0.4 |
|                      | 39       | x64           | 8.0.4 |
|                      | 40       | x64           | 8.0.4 |
| Ubuntu               | 20.04    | x64           | 8.0.4 |
|                      | 22.04    | x64           | 8.0.4 |
|                      | 24.04    | x64           | 8.0.4 |

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
