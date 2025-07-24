/*
 * Copyright (C) 2025 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.authlete.hms.fapi;


import java.security.SignatureException;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureEntry;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.impl.JoseHttpVerifier;
import com.nimbusds.jose.jwk.JWK;


/**
 * A utility for verifying a resource request in accordance with
 * the FAPI 2&#x2E;0 Http Signatures requirements.
 *
 * <p><b>Sample Code</b></p>
 *
 * <pre>
 * <span style="color: green;">// The received signature.</span>
 * SignatureEntry signatureEntry = ...;
 * byte[]            signature = signatureEntry.getSignature();
 * SignatureMetadata metadata  = signatureEntry.getMetadata();
 *
 * <span style="color: green;">// Create a verifier.</span>
 * FapiResourceRequestVerifier verifier = new FapiResourceRequestVerifier()
 *         .setMethod(<span style="color: darkred;">"POST"</span>)
 *         .setTargetUri(URI.create(<span style="color: darkred;"
 *          >"https://example.com/path?key=value"</span>))
 *         .setAuthorization(<span style="color: darkred;">"Bearer abc"</span>)
 *         .setContentDigest(
 *             <span style="color: darkred;">"sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7<!--
 *             -->T8If536DEMBg9hyq/4o=:"</span>
 *         )
 *         .setVerificationKey(JWK.parse(VERIFICATION_KEY))
 *         ;
 *
 * <span style="color: green;">// Verify the signature.</span>
 * boolean verified = verifier.verify(signature, metadata);
 * </pre>
 *
 * @since 1.4
 *
 * @see <a href="https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html"
 *      >FAPI 2.0 Http Signatures</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html"
 *      >RFC 9421: HTTP Message Signatures</a>
 */
public class FapiResourceRequestVerifier extends FapiResourceRequestBase<FapiResourceRequestVerifier>
{
    /**
     * The public key for verifying the HTTP message signature in the request.
     */
    private JWK verificationKey;


    /**
     * Get the public key for verifying the HTTP message signature in the request.
     *
     * @return
     *         The public key for verifying the HTTP message signature.
     */
    public JWK getVerificationKey()
    {
        return verificationKey;
    }


    /**
     * Set the public key for verifying the HTTP message signature in the request.
     *
     * @param verificationKey
     *         The public key for verifying the HTTP message signature.
     *
     * @return
     *         {@code this} object.
     */
    public FapiResourceRequestVerifier setVerificationKey(JWK verificationKey)
    {
        this.verificationKey = verificationKey;

        return this;
    }


    @Override
    String getKeyID()
    {
        if (getVerificationKey() != null)
        {
            return getVerificationKey().getKeyID();
        }

        return null;
    }


    /**
     * Execute HTTP message verification.
     *
     * <p>
     * This method is an alias of {@link #verify(byte[], SignatureMetadata)
     * verify}{@code (signatureEntry.getSignature(), signatureEntry.getMetadata())}.
     * </p>
     *
     * @param signatureEntry
     *         A signature entry that contains the signature to be verified.
     *
     * @return
     *         The result of signature verification.
     *
     * @throws IllegalStateException
     *         Mandatory input parameters, such as {@code method},
     *         {@code targetUri}, {@code authorization}, and
     *         {@code verificationKey}, are not set.
     *
     * @throws SignatureException
     *         Signature verification failed.
     */
    public boolean verify(SignatureEntry signatureEntry) throws IllegalStateException, SignatureException
    {
        return verify(signatureEntry.getSignature(), signatureEntry.getMetadata());
    }


    /**
     * Execute HTTP message verification.
     *
     * @param signature
     *         The signature to verify.
     *
     * @param metadata
     *         The signature metadata referenced for creating the signature base.
     *         If {@code null} is given, the default signature metadata is built
     *         and used, but it is not recommended. The signature metadata that
     *         has been provided together with the signature should be used.
     *
     * @return
     *         The result of signature verification.
     *
     * @throws IllegalStateException
     *         Mandatory input parameters, such as {@code method},
     *         {@code targetUri}, {@code authorization}, and
     *         {@code verificationKey}, are not set.
     *
     * @throws SignatureException
     *         Signature verification failed.
     */
    public boolean verify(byte[] signature, SignatureMetadata metadata) throws IllegalStateException, SignatureException
    {
        // Check if a verification key is set.
        checkVerificationKey();

        // Create the signature base.
        SignatureBase base = createSignatureBase(metadata);

        // Verify the signature.
        return verify(signature, base);
    }


    private void checkVerificationKey()
    {
        JWK key = getVerificationKey();

        if (key == null)
        {
            throw new IllegalStateException(
                    "A public key for verifying the HTTP message signature " +
                    "in the request must be set in advance using the " +
                    "setVerificationKey(JWK) method.");
        }

        if (key.isPrivate())
        {
            throw new IllegalStateException(
                    "The key set by the setVerificationKey(JWK) method is not " +
                    "a public key.");
        }
    }


    private boolean verify(byte[] signature, SignatureBase base) throws SignatureException
    {
        // Verify the signature using the specified verification key.
        return base.verify(new JoseHttpVerifier(getVerificationKey()), signature);
    }
}
