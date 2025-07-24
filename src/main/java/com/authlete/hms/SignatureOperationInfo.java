/*
 * Copyright (C) 2025 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.authlete.hms;


import org.greenbytes.http.sfv.ByteSequenceItem;


/**
 * The base class for {@link SigningInfo} and {@link VerificationInfo}.
 *
 * @param <T>
 *         The subclass.
 *
 * @since 1.5
 */
public class SignatureOperationInfo<T extends SignatureOperationInfo<T>>
{
    /**
     * The computed signature base.
     */
    private SignatureBase signatureBase;


    /**
     * The signature.
     */
    private byte[] signature;


    /**
     * Get the computed signature base.
     *
     * @return
     *         The computed signature base.
     */
    public SignatureBase getSignatureBase()
    {
        return signatureBase;
    }


    /**
     * Set the computed signature base.
     *
     * @param base
     *         The computed signature base.
     *
     * @return
     *         {@code this} object.
     */
    @SuppressWarnings("unchecked")
    public T setSignatureBase(SignatureBase base)
    {
        this.signatureBase = base;

        return (T)this;
    }


    /**
     * Get the signature metadata.
     *
     * @return
     *         The signature metadata.
     */
    public SignatureMetadata getMetadata()
    {
        // signature-base
        SignatureBase base = getSignatureBase();

        if (base == null)
        {
            return null;
        }

        // signature-params-line
        SignatureParamsLine paramsLine = base.getParamsLine();

        if (paramsLine == null)
        {
            return null;
        }

        // The value of the signature-params-line (= signature metadata)
        return paramsLine.getMetadata();
    }


    /**
     * Get the signature metadata in the serialized form. The value can be
     * used as part of the {@code Signature-Input} HTTP field value.
     *
     * <p><b>Sample Code</b></p>
     *
     * <pre>
     * String signatureInputFieldValue =
     *     String.format(<span style="color: darkred;">"sig=%s"</span>, <!--
     *     -->info.getSerializedSignatureMetadata());
     *
     * responseBuilder.header(
     *     <span style="color: darkred;">"Signature-Input"</span>, signatureInputFieldValue);
     * </pre>
     *
     * @return
     *         The signature metadata in the serialized form.
     */
    public String getSerializedSignatureMetadata()
    {
        // The signature metadata.
        SignatureMetadata metadata = getMetadata();

        if (metadata == null)
        {
            return null;
        }

        // Signature metadata in the serialized form.
        return metadata.serialize();
    }


    /**
     * Get the signature.
     *
     * @return
     *         The signature.
     */
    public byte[] getSignature()
    {
        return signature;
    }


    /**
     * Set the signature.
     *
     * @param signature
     *         The signature.
     *
     * @return
     *         {@code this} object.
     */
    @SuppressWarnings("unchecked")
    public T setSignature(byte[] signature)
    {
        this.signature = signature;

        return (T)this;
    }


    /**
     * Get the signature in the serialized form. The value can be used as
     * part of the {@code Signature} HTTP field value.
     *
     * <p><b>Sample Code</b></p>
     *
     * <pre>
     * String signatureFieldValue =
     *     String.format(<span style="color: darkred;">"sig=%s"</span>, <!--
     *     -->info.getSerializedSignature());
     *
     * responseBuilder.header(
     *     <span style="color: darkred;">"Signature"</span>, signatureFieldValue);
     * </pre>
     *
     * @return
     *         The signature in the serialized form.
     */
    public String getSerializedSignature()
    {
        byte[] sig = getSignature();

        if (sig == null)
        {
            return null;
        }

        // Serialize the byte array into a byte sequence as defined in RFC 8941.
        return ByteSequenceItem.valueOf(sig).serialize();
    }
}
