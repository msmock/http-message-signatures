/*
 * Copyright (C) 2024-2025 Authlete, Inc.
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
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SigningInfo;
import com.authlete.hms.impl.JoseHttpSigner;
import com.nimbusds.jose.jwk.JWK;


/**
 * A utility for signing a resource response in accordance with
 * the FAPI 2&#x2E;0 Http Signatures requirements.
 *
 * <p><b>Sample Code</b></p>
 *
 * <pre>
 * <span style="color: green;">// Create a signer.</span>
 * FapiResourceResponseSigner signer = new FapiResourceResponseSigner()
 *         .setMethod(<span style="color: darkred;">"GET"</span>)
 *         .setTargetUri(URI.create(<span style="color: darkred;"
 *          >"https://example.com/path?key=value"</span>))
 *         .setAuthorization(<span style="color: darkred;"
 *          >"Bearer abc"</span>)
 *         .setStatus(200)
 *         .setResponseContentDigest(
 *             <span style="color: darkred;">"sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7<!--
 *             -->T8If536DEMBg9hyq/4o=:"</span>
 *         )
 *         .setCreated(Instant.now())
 *         .setSigningKey(JWK.parse(SIGNING_KEY))
 *         ;
 *
 * <span style="color: green;">// Sign the HTTP response.</span>
 * SignatureInfo info = signer.sign();
 *
 * <span style="color: green;">// Signature HTTP field.</span>
 * String signatureFieldValue = String.format(<span style="color: darkred;"
 *     >"sig=%s"</span>, info.getSerializedSignature());
 *     <span style="color: green;">// e.g. sig=:OXJQdFoyuYsbMfJHl/+bT8WwKv49Pt6<!--
 *     -->fiYz/0bTQSAynaJH+HELTqZVzzm3/pyk/MPrjQ9iPmPxz8rgkkRe5kQ==:</span>
 * responseBuilder.header(<span style="color: darkred;">"Signature"</span>, signatureFieldValue);
 *
 * <span style="color: green;">// Signature-Input HTTP field.</span>
 * String signatureInputFieldValue = String.format(<span style="color: darkred;"
 *     >"sig=%s"</span>, info.getSerializedSignatureMetadata());
 *     <span style="color: green;">// e.g. sig=("@method";req "@target-uri";req <!--
 *     -->"@status" "content-digest");created=1729584639;keyid="snIZq-_NvzkKV-Id<!--
 *     -->iM348BCz_RKdwmufnrPubsKKyio";tag="fapi-2-response"</span>
 * responseBuilder.header(<span style="color: darkred;">"Signature-Input"</span>, signatureInputFieldValue);
 * </pre>
 *
 * @since 1.3
 *
 * @see <a href="https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html"
 *      >FAPI 2.0 Http Signatures</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html"
 *      >RFC 9421: HTTP Message Signatures</a>
 */
public class FapiResourceResponseSigner extends FapiResourceResponseBase<FapiResourceResponseSigner>
{
    /**
     * The private key for signing the signature base.
     */
    private JWK signingKey;


    /**
     * Get the private key for signing the HTTP response.
     *
     * @return
     *         The private key for signing the HTTP response.
     */
    public JWK getSigningKey()
    {
        return signingKey;
    }


    /**
     * Set the private key for signing the HTTP response.
     *
     * @param signingKey
     *         The private key for signing the HTTP response.
     *
     * @return
     *         {@code this} object.
     */
    public FapiResourceResponseSigner setSigningKey(JWK signingKey)
    {
        this.signingKey = signingKey;

        return this;
    }


    @Override
    String getKeyID()
    {
        if (getSigningKey() != null)
        {
            return getSigningKey().getKeyID();
        }

        return null;
    }


    /**
     * Execute HTTP message signing.
     *
     * <p>
     * This method is an alias of {@link #sign(SignatureMetadata) sign}{@code (null)}.
     * </p>
     *
     * @return
     *         Information about the signing operation, including the
     *         computed signature base and the generated signature.
     *
     * @throws IllegalStateException
     *         Mandatory input parameters, such as {@code method},
     *         {@code targetUri}, {@code status}, and {@code signingKey},
     *         are not set.
     *
     * @throws SignatureException
     *         Signing failed.
     */
    public SigningInfo sign() throws IllegalStateException, SignatureException
    {
        return sign((SignatureMetadata)null);
    }


    /**
     * Execute HTTP message signing.
     *
     * @param metadata
     *         The signature metadata referenced for creating the signature base.
     *         If {@code null} is given, the default signature metadata is built
     *         and used.
     *
     * @return
     *         Information about the signing operation, including the
     *         computed signature base and the generated signature.
     *
     * @throws IllegalStateException
     *         Mandatory input parameters, such as {@code method},
     *         {@code targetUri}, {@code status}, and {@code signingKey},
     *         are not set.
     *
     * @throws SignatureException
     *         Signing failed.
     */
    public SigningInfo sign(SignatureMetadata metadata) throws IllegalStateException, SignatureException
    {
        // Check if a signing key is set.
        checkSigningKey();

        // Create the signature base.
        SignatureBase base = createSignatureBase(metadata);

        // Sign the signature base with the specified signing key.
        byte[] signature = sign(base);

        // Collect information about the signing operation.
        SigningInfo info = new SigningInfo()
                .setSigningKey(getSigningKey())
                .setSignatureBase(base)
                .setSignature(signature)
                ;

        return info;
    }


    private void checkSigningKey()
    {
        JWK key = getSigningKey();

        if (key == null)
        {
            throw new IllegalStateException(
                    "A private key for signing the HTTP response must be set " +
                    "using the setSigningKey(JWK) method in advance.");
        }

        if (!key.isPrivate())
        {
            throw new IllegalStateException(
                    "The key set by the setSigningKey(JWK) method is not a " +
                    "private key.");
        }
    }


    private byte[] sign(SignatureBase base) throws SignatureException
    {
        // Sign the signature base using the specified signing key.
        return base.sign(new JoseHttpSigner(getSigningKey()));
    }
}
