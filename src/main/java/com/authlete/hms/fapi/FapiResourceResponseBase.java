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


import java.net.URI;
import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentIdentifierParameters;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureBaseBuilder;
import com.authlete.hms.SignatureContext;
import com.authlete.hms.SignatureEntry;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;


/**
 * The base class for {@link FapiResourceResponseSigner} and
 * {@link FapiResourceResponseVerifier}.
 *
 * @param <T>
 *         The subclass.
 *
 * @since 1.4
 *
 * @see <a href="https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html"
 *      >FAPI 2.0 Http Signatures</a>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html"
 *      >RFC 9421: HTTP Message Signatures</a>
 */
public abstract class FapiResourceResponseBase<T extends FapiResourceResponseBase<T>>
{
    /**
     * The component identifier, {@code "@method";req}.
     */
    private static final ComponentIdentifier COMP_ID_METHOD_REQ =
            new ComponentIdentifier("@method",
                    new ComponentIdentifierParameters().setReq(true));


    /**
     * The component identifier, {@code "@target-uri";req}.
     */
    private static final ComponentIdentifier COMP_ID_TARGET_URI_REQ =
            new ComponentIdentifier("@target-uri",
                    new ComponentIdentifierParameters().setReq(true));


    /**
     * The component identifier, {@code "content-digest";req}.
     */
    private static final ComponentIdentifier COMP_ID_CONTENT_DIGEST_REQ =
            new ComponentIdentifier("content-digest",
                    new ComponentIdentifierParameters().setReq(true));


    /**
     * The component identifier, {@code "@status"}.
     */
    private static final ComponentIdentifier COMP_ID_STATUS =
            new ComponentIdentifier("@status");


    /**
     * The component identifier, {@code "content-digest"}.
     */
    private static final ComponentIdentifier COMP_ID_CONTENT_DIGEST =
            new ComponentIdentifier("content-digest");


    /**
     * The value of the {@code tag} parameter of the signature metadata.
     */
    private static final String TAG_VALUE_FAPI_2_RESPONSE = "fapi-2-response";


    /**
     * The HTTP method of the request.
     */
    private String method;


    /**
     * The target URI (the original request URL) of the HTTP request.
     */
    private URI targetUri;


    /**
     * The value of the {@code Content-Digest} HTTP field of the request.
     */
    private String requestContentDigest;


    /**
     * The value of the three-digit numeric HTTP status code of the response.
     */
    private int status;


    /**
     * The value of the {@code Content-Digest} HTTP field of the response.
     */
    private String responseContentDigest;


    /**
     * The value of the {@code created} parameter of the signature metadata.
     */
    private Long created;


    /**
     * The list of signature entries in the request.
     */
    private List<SignatureEntry> requestSignatures = new ArrayList<>();


    /**
     * Get the HTTP method of the request. This is used as the value of the
     * {@code "@method";req} derived component.
     *
     * @return
     *         The HTTP method of the request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    public String getMethod()
    {
        return method;
    }


    /**
     * Set the HTTP method of the request. This is used as the value of the
     * {@code "@method";req} derived component.
     *
     * @param method
     *         The HTTP method of the request.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.1"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.1. Method</a>
     */
    @SuppressWarnings("unchecked")
    public T setMethod(String method)
    {
        this.method = method;

        return (T)this;
    }


    /**
     * Get the target URI (the original request URL) of the HTTP request.
     * This is used as the value of the {@code "@target-uri";req} derived
     * component.
     *
     * @return
     *         The target URI (the original request URL) of the HTTP request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    public URI getTargetUri()
    {
        return targetUri;
    }


    /**
     * Set the target URI (the original request URL) of the HTTP request.
     * This is used as the value of the {@code "@target-uri";req} derived
     * component.
     *
     * @param targetUri
     *         The target URI (the original request URL) of the HTTP request.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.2"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.2. Target URI</a>
     */
    @SuppressWarnings("unchecked")
    public T setTargetUri(URI targetUri)
    {
        this.targetUri = targetUri;

        return (T)this;
    }


    /**
     * Get the value of the {@code Content-Digest} HTTP field of the request.
     * This is used as the value of the {@code "content-digest";req} component.
     *
     * @return
     *         The value of the {@code Content-Digest} HTTP field of the request.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    public String getRequestContentDigest()
    {
        return requestContentDigest;
    }


    /**
     * Set the value of the {@code Content-Digest} HTTP field of the request.
     * This is used as the value of the {@code "content-digest";req} component.
     *
     * @param contentDigest
     *         The value of the {@code Content-Digest} HTTP field of the request.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    @SuppressWarnings("unchecked")
    public T setRequestContentDigest(String contentDigest)
    {
        this.requestContentDigest = contentDigest;

        return (T)this;
    }


    /**
     * Get the status code of the HTTP response. This is used as the value of
     * the {@code "@status"} derived component.
     *
     * @return
     *         The status code of the HTTP response.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    public int getStatus()
    {
        return status;
    }


    /**
     * Set the status code of the HTTP response. This is used as the value of
     * the {@code "@status"} derived component.
     *
     * @param status
     *         The status code of the HTTP response.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.9"
     *      >RFC 9421: HTTP Message Signatures, Section 2.2.9. Status Code</a>
     */
    @SuppressWarnings("unchecked")
    public T setStatus(int status)
    {
        this.status = status;

        return (T)this;
    }


    /**
     * Get the value of the {@code Content-Digest} HTTP field of the response.
     * This is used as the value of the {@code "content-digest"} component.
     *
     * @return
     *         The value of the {@code Content-Digest} HTTP field of the response.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    public String getResponseContentDigest()
    {
        return responseContentDigest;
    }


    /**
     * Set the value of the {@code Content-Digest} HTTP field of the response.
     * This is used as the value of the {@code "content-digest"} component.
     *
     * @param contentDigest
     *         The value of the {@code Content-Digest} HTTP field of the response.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9530.html"
     *      >RFC 9530: Digest Fields</a>
     */
    @SuppressWarnings("unchecked")
    public T setResponseContentDigest(String contentDigest)
    {
        this.responseContentDigest = contentDigest;

        return (T)this;
    }


    /**
     * Get the creation time of the signature, represented as seconds since
     * the Unix epoch. This is used as the value of the {@code created}
     * parameter of the signature metadata.
     *
     * @return
     *         The creation time of the signature.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421: HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    public Long getCreated()
    {
        return created;
    }


    /**
     * Set the creation time of the signature, represented as seconds since
     * the Unix epoch. This is used as the value of the {@code created}
     * parameter of the signature metadata.
     *
     * <p>
     * If this is not set before the signing or verifying operation, the
     * current time at which the operation will be executed is used as the
     * signature creation time.
     * </p>
     *
     * @param created
     *         The creation time of the signature.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421: HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    @SuppressWarnings("unchecked")
    public T setCreated(Long created)
    {
        this.created = created;

        return (T)this;
    }


    /**
     * Set the creation time of the signature. This is used as the value of
     * the {@code created} parameter of the signature metadata.
     *
     * <p>
     * If this is not set before the signing or verifying operation, the
     * current time at which the operation will be executed is used as the
     * signature creation time.
     * </p>
     *
     * @param created
     *         The creation time of the signature.
     *
     * @return
     *         {@code this} object.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3"
     *      >RFC 9421: HTTP Message Signatures, Section 2.3. Signature Parameters</a>
     */
    public T setCreated(Instant created)
    {
        Long timestamp = null;

        if (created != null)
        {
            // Seconds since the Unix epoch.
            timestamp = created.getEpochSecond();
        }

        return setCreated(timestamp);
    }


    private Long getCreatedOrNow()
    {
        // The value of the 'created' parameter held by this instance.
        Long timestamp = getCreated();

        // If the 'created' parameter has not been set.
        if (timestamp == null)
        {
            // The current time (= seconds since the Unix epoch).
            timestamp = Instant.now().getEpochSecond();
        }

        return timestamp;
    }


    /**
     * Get the list of signature entries that represent HTTP message signatures
     * in the request.
     *
     * @return
     *         The list of signature entries.
     */
    public List<SignatureEntry> getRequestSignatures()
    {
        return requestSignatures;
    }


    /**
     * Add a signature entry that represents an HTTP message signature in the
     * request.
     *
     * <p>
     * Note that signature entries that do not have the {@code fapi-2-request}
     * tag should not be added.
     * </p>
     *
     * @param entry
     *         A signature entry.
     *
     * @return
     *         {@code this} object.
     */
    @SuppressWarnings("unchecked")
    public T addRequestSignature(SignatureEntry entry)
    {
        if (entry != null)
        {
            requestSignatures.add(entry);
        }

        return (T)this;
    }


    /**
     * Add signature entries that represent HTTP message signatures in the
     * request.
     *
     * <p>
     * Note that signature entries that do not have the {@code fapi-2-request}
     * tag should not be added.
     * </p>
     *
     * @param entries
     *         The list of signature entries.
     *
     * @return
     *         {@code this} object.
     */
    @SuppressWarnings("unchecked")
    public T addRequestSignatures(Collection<SignatureEntry> entries)
    {
        if (entries != null)
        {
            entries.forEach(this::addRequestSignature);
        }

        return (T)this;
    }


    /**
     * Create the signature base.
     *
     * @param metadata
     *         The signature metadata referenced for creating the signature base.
     *         If {@code null} is given, the default signature metadata is built
     *         and used.
     *
     * @return
     *         The signature base.
     *
     * @throws IllegalStateException
     *         Mandatory input parameters, such as {@code method},
     *         {@code targetUri}, and {@code status}, are not set.
     *
     * @throws SignatureException
     *         The value of a derived component is not available.
     */
    SignatureBase createSignatureBase(SignatureMetadata metadata)
            throws IllegalStateException, SignatureException
    {
        // Check if input parameters have been properly set.
        checkParameters();

        if (metadata == null)
        {
            metadata = createDefaultMetadata();
        }

        return new SignatureBaseBuilder(new Context()).build(metadata);
    }


    private void checkParameters()
    {
        // method
        checkParameter("The HTTP method of the request",
                getMethod(), "setMethod(String)");

        // targetUri
        checkParameter("The target URI (the original request URL) of the HTTP request",
                getTargetUri(), "setTargetUri(URI)");

        // status
        checkParameterStatus(getStatus());
    }


    private static void checkParameter(
            String parameterName, Object parameterValue, String setterMethod)
    {
        // If the parameter value is not null.
        if (parameterValue != null)
        {
            // OK.
            return;
        }

        throw new IllegalStateException(String.format(
                "%s must be set using the %s method before calling the sign() method.",
                parameterName, setterMethod));
    }


    private static void checkParameterStatus(int status)
    {
        // If the status is a three-digit, positive integer.
        if (100 <= status && status < 1000)
        {
            // OK.
            return;
        }

        // The status code value is outside the valid range.

        // If it appears that neither of the setStatus methods has been called.
        if (status == 0)
        {
            throw new IllegalStateException(
                    "The status code of the response must be set using the " +
                    "setStatus(int) or setStatus(Instant) method before calling "+
                    "the sign() method.");
        }

        throw new IllegalStateException(
                "The status code of the response must be a three-digit, positive integer.");
    }


    private final class Context implements SignatureContext
    {
        @Override
        public String getComponentValue(
                SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException
        {
            // "@method";req
            if (identifier.equals(COMP_ID_METHOD_REQ))
            {
                return getMethod();
            }

            // "@target-uri";req
            if (identifier.equals(COMP_ID_TARGET_URI_REQ))
            {
                return (getTargetUri() != null) ? getTargetUri().toASCIIString() : null;
            }

            // "content-digest";req
            if (identifier.equals(COMP_ID_CONTENT_DIGEST_REQ))
            {
                return getRequestContentDigest();
            }

            // "@status"
            if (identifier.equals(COMP_ID_STATUS))
            {
                return String.valueOf(getStatus());
            }

            // "content-digest"
            if (identifier.equals(COMP_ID_CONTENT_DIGEST))
            {
                return getResponseContentDigest();
            }

            String  name = identifier.getComponentName();
            boolean req  = identifier.getParameters().isReq();
            String  key  = identifier.getParameters().getKey();

            // "signature";req;key="{key}"
            if (name.equals("signature") && req && key != null)
            {
                // ":{base64-encoded-signature}:" or null
                return getRequestSignatures().stream()
                        .filter(entry -> entry.getLabel().equals(key))
                        .map(SignatureEntry::getSignature)
                        .map(signature -> Base64.getEncoder().encodeToString(signature))
                        .map(base64 -> String.format(":%s:", base64))
                        .findFirst()
                        .orElse(null);
            }

            // "signature-input";req;key="{key}"
            if (name.equals("signature-input") && req && key != null)
            {
                // "{signature-metadata}" or null
                return getRequestSignatures().stream()
                        .filter(entry -> entry.getLabel().equals(key))
                        .map(SignatureEntry::getMetadata)
                        .map(SignatureMetadata::serialize)
                        .findFirst()
                        .orElse(null);
            }

            return null;
        }
    }


    private SignatureMetadata createDefaultMetadata()
    {
        // NOTE: The order here affects signature generation and verification.

        //------------------------------------------------------------
        // identifiers
        //------------------------------------------------------------
        List<ComponentIdentifier> identifiers = new ArrayList<>();

        // "@method";req
        identifiers.add(COMP_ID_METHOD_REQ);

        // "@target-uri";req
        identifiers.add(COMP_ID_TARGET_URI_REQ);

        if (getRequestContentDigest() != null)
        {
            // "content-digest";req
            identifiers.add(COMP_ID_CONTENT_DIGEST_REQ);
        }

        getRequestSignatures().forEach(signatureEntry -> {
            // "signature";req;key="{label}"
            identifiers.add(buildComponentIdentifierSignature(signatureEntry));

            // "signature-input";req;key="{label}"
            identifiers.add(buildComponentIdentifierSignatureInput(signatureEntry));
        });

        // "@status"
        identifiers.add(COMP_ID_STATUS);

        if (getResponseContentDigest() != null)
        {
            // "content-digest"
            identifiers.add(COMP_ID_CONTENT_DIGEST);
        }

        //------------------------------------------------------------
        // parameters
        //------------------------------------------------------------
        SignatureMetadataParameters parameters = new SignatureMetadataParameters();

        // created
        parameters.setCreated(getCreatedOrNow());

        if (getKeyID() != null)
        {
            // keyid
            parameters.setKeyid(getKeyID());
        }

        // tag
        parameters.setTag(TAG_VALUE_FAPI_2_RESPONSE);

        //------------------------------------------------------------
        // metadata
        //------------------------------------------------------------
        return new SignatureMetadata(identifiers, parameters);
    }


    private static ComponentIdentifier buildComponentIdentifierSignature(SignatureEntry signatureEntry)
    {
        // "signature";req;key="{label}"
        return new ComponentIdentifier("signature",
                new ComponentIdentifierParameters().setReq(true).setKey(signatureEntry.getLabel()));
    }


    private static ComponentIdentifier buildComponentIdentifierSignatureInput(SignatureEntry signatureEntry)
    {
        // "signature-input";req;key="{label}"
        return new ComponentIdentifier("signature-input",
                new ComponentIdentifierParameters().setReq(true).setKey(signatureEntry.getLabel()));
    }


    /**
     * Get the key ID of the signing key or the verification key, if available.
     * This is used as the value of the {@code keyid} parameter of the
     * signature metadata.
     */
    abstract String getKeyID();
}
