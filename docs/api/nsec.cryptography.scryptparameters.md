# ScryptParameters Struct

Contains parameters for the [[creation of a Scrypt instance|PasswordBasedKeyDerivationAlgorithm Class#Scrypt(in ScryptParameters)]].

    public struct ScryptParameters


## [TOC] Summary


## Constructors


### ScryptParameters()

Initializes a new instance of [[ScryptParameters|ScryptParameters Struct]]
with all fields set to zero.

    public ScryptParameters()


## Fields


### BlockSize

Gets or sets the *block size* parameter (r) of scrypt.

    public int BlockSize;

#### Field Value

A positive integer that specifies the block size.


### Cost

Gets or sets the *CPU/Memory cost* parameter (N) of scrypt.

    public long Cost;

#### Field Value

An integer number larger than 1, a power of 2, and less than 2^(128 * r / 8)
that specifies the CPU/Memory cost.


### Parallelization

Gets or sets the *parallelization* parameter (p) of scrypt.

    public int Parallelization;

#### Field Value

A positive integer less than or equal to ((2^32-1) * 32) / (128 * r) that
specifies the amount of parallelism desired.


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[PasswordBasedKeyDerivationAlgorithm Class]]
