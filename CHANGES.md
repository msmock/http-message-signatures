CHANGES
=======

1.6 (2025-08-28)
----------------

- `FapiResourceResponseBase` class
  * Add the `getAuthorization()` method.
  * Add the `setAuthorization(String)` method.
  * Add the `getDpop()` method.
  * Add the `setDpop(String)` method.
  * Remove the `getRequestSignatures()` method.
  * Remove the `addRequestSignature(SignatureEntry)` method.
  * Remove the `addRequestSignatures(Collection<SignatureEntry>)` method.

1.5 (2025-07-25)
----------------

- `FapiResourceRequestVerifier` class
  * Change the return type of the `verify` methods from `boolean` to `VerificationInfo`.
  * Implement additional verification steps on the signature metadata.

- `FapiResourceResponseVerifier` class
  * Change the return type of the `verify` methods from `boolean` to `VerificationInfo`.
  * Implement additional verification steps on the signature metadata.

- `SigningInfo` class
  * Renamed from `SignatureInfo`.
  * `extends` the `SignatureOperationInfo` class.

- New types
  * `FapiResourceVerificationUtility` class.
  * `SignatureOperationInfo` class.
  * `VerificationInfo` class.

1.4 (2025-07-24)
----------------

- `FapiResourceResponseSigner` class
  * `extends` the `FapiResourceResponseBase` class.

- New types
  * `FapiResourceRequestBase` class
  * `FapiResourceRequestSigner` class
  * `FapiResourceRequestVerifier` class
  * `FapiResourceResponseBase` class
  * `FapiResourceResponseVerifier` class
  * `SignatureEntry` class

1.3 (2024-10-22)
----------------

- `StructuredDataType` class
  * Add an entry for `"content-digest"`.
  * Add an entry for `"repr-digest"`.
  * Add an entry for `"want-content-digest"`.
  * Add an entry for `"want-repr-digest"`.

- New types
  * `SignatureInfo` class
  * `FapiResourceResponseSigner` class

1.2 (2024-10-03)
----------------

- `StructuredFieldToken` class
  * Fixed a bug in the regular expression.

1.1 (2024-10-01)
----------------

- New types
  * `ComponentValueProvider` class
  * `DerivedComponentValueProvider` class
  * `NormalComponentValueProvider` class
  * `StructuredDataType` enum

1.0 (2024-09-24)
----------------

- The initial implementation.
