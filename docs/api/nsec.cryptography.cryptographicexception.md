# CryptographicException Class

Represents a cryptography-related exception.

    public class CryptographicException : Exception


## [TOC] Summary


## Constructors


### CryptographicException()

Initializes a new instance of the CryptographicException class.

    public CryptographicException()


### CryptographicException(string)

Initializes a new instance of the CryptographicException class with a specified
error message.

    public CryptographicException(
        string message)

* Parameters

    message
    : An error message that explains the reason for the exception.


### CryptographicException(string, Exception)

Initializes a new instance of the CryptographicException class with a specified
error message and a reference to the inner exception that is the cause of this
exception.

    public CryptographicException(
        string message,
        Exception innerException)

* Parameters

    message
    : An error message that explains the reason for the exception.

    innerException
    : The exception that is the cause of the current exception.
