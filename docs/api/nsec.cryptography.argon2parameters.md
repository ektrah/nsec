# Argon2Parameters Struct

Contains parameters for the [[creation of an Argon2id instance|PasswordBasedKeyDerivationAlgorithm Class#Argon2id(in Argon2Parameters)]].

    public struct Argon2Parameters


## [TOC] Summary


## Constructors


### Argon2Parameters()

Initializes a new instance of [[Argon2Parameters|Argon2Parameters Struct]]
with all fields set to zero.

    public Argon2Parameters()


## Fields


### DegreeOfParallelism

Gets or sets the *degree of parallelism* parameter (p) of Argon2. The degree of
parallelism determines how many independent (but synchronizing) computational
chains (lanes) can be run.

    public int DegreeOfParallelism;

#### Field Value

An integer value from 1 to 2^24-1 that specifies the degree of parallelism.

!!! Note
    Any value other than 1 is not supported at this time.


### MemorySize

Gets or sets the *memory size* parameter (m) of Argon2. 

    public long MemorySize;

#### Field Value

An integer number of kibibytes from 8 to 2^32-1 that specifies the memory size.


### NumberOfPasses

Gets or sets the *number of passes* parameter (t) of Argon2. The number of
passes can be used to tune the running time independently of the memory size.

    public long NumberOfPasses;

#### Field Value

An integer number from 1 to 2^32-1 that specifies the number of passes.


## Thread Safety

Any public static members of this type are thread safe. Any instance members are
not guaranteed to be thread safe.


## See Also

* API Reference
    * [[PasswordBasedKeyDerivationAlgorithm Class]]
