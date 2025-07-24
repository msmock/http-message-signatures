# Java Library for RFC 9421 HTTP Message Signatures

## License

  Apache License, Version 2.0

## Maven

```xml
<dependency>
    <groupId>com.authlete</groupId>
    <artifactId>http-message-signatures</artifactId>
    <version>${http-message-signatures.version}</version>
</dependency>
```

Check the [CHANGES.md](CHANGES.md) file to know the latest version.

## Source Code

  <code>https://github.com/authlete/http-message-signatures</code>

## JavaDoc

  <code>https://authlete.github.io/http-message-signatures</code>

## Standard Specifications

The following is a non-exhaustive list of standard specifications related to
HTTP Message Signatures.

### IETF RFC

- [RFC 8941][RFC_8941] Structured Field Values for HTTP
- [RFC 9421][RFC_9421] HTTP Message Signatures

### IANA Assignments

- IANA: [HTTP Message Signature][IANA_HTTP_MESSAGE_SIGNATURE]

### OpenID

- [FAPI 2.0 Http Signatures][FAPI_20_HTTP_SIGNATURES]

## Overview

The general steps for generating an HTTP message signature are as follows:

1. Create a Signature Base.
2. Generate a signature over the Signature Base.
3. Place the signature in the `Signature` HTTP field.
4. Place the signature metadata in the `Signature-Input` HTTP field.

The general steps for verifying an HTTP message signature are as follows:

1. Extract the signature from the `Signature` HTTP field.
2. Extract the signature metadata from the `Signature-Input` HTTP field.
3. Reconstruct the Signature Base.
4. coVerify that the signature is valid for the Signature Base.

## Details

### Create a Signature Base

The `SignatureBase` class represents a Signature Base.

The `SignatureBaseBuilder` class is a utility for creating instances of the
`SignatureBase` class. It requires an implementation of the `SignatureContext`
interface and an instance of the `SignatureMetadata` class as input.

The `SignatureContext` interface has a single method that returns the value
corresponding to a specified component identifier:

```java
String getComponentValue(
        SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException;
```

The following code is an example implementation of the `SignatureContext`
interface that returns only the value of the derived component `@method`:

```java
public class Context implements SignatureContext
{
    // The component identifier that represents "@method".
    private static final ComponentIdentifier COMP_ID_METHOD = new ComponentIdentifier("@method");

    @Override
    String getComponentValue(
            SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException
    {
        // "@method"
        if (identifier.equals(COMP_ID_METHOD))
        {
            return "GET";
        }

        return null;
    }
}
```

The `SignatureMetadata` class represents the list of components and parameters
that are subject to signing. The following code shows an example of creating a
`SignatureMetadata` instance that includes only `@method`:

```java
List<ComponentIdentifier> identifiers = Arrays.asList(
        new ComponentIdentifier("@method")
);

SignatureMetadata metadata = new SignatureMetadata(identifiers);
```

Using the instances of `SignatureContext` and `SignatureMetadata`, you can
create a `SignatureBase` instance as follows:

```java
SignatureBase base = new SignatureBaseBuilder(context).build(metadata);
```

### Signing

You can generate a signature by calling the `sign(HttpSigner)` method of the
`SignatureBase` class:

```java
public byte[] sign(HttpSigner signer) throws SignatureException
```

The `HttpSigner` interface, which is the argument to the `sign` method of the
`SignatureBase` class, is an interface that has a single method. This method
takes a serialized Signature Base as input and returns a signature:

```java
byte[] sign(byte[] signatureBase) throws SignatureException;
```

Using the `JoseHttpSigner` class, which is an implementation of the
`HttpSigner` interface included in this library, the signing process can be
written as follows:

```java
JWK signingKey = ...;

byte[] signature = base.sign(new JoseHttpSigner(signingKey));
```

TBW

## Contact

Authlete Contact Form: https://www.authlete.com/contact/

<!-- ==================== LINKS ==================== -->

[RFC_8941]: https://www.rfc-editor.org/rfc/rfc8941.html
[RFC_9421]: https://www.rfc-editor.org/rfc/rfc9421.html

[IANA_HTTP_MESSAGE_SIGNATURE]: https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml

[FAPI_20_HTTP_SIGNATURES]: https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html
