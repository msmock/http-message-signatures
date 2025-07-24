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
package com.authlete.hms;


import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;


/**
 * Signature entry, a pack of label, signature, and signature metadata.
 *
 * @since 1.4
 */
public class SignatureEntry
{
    /**
     * The label assigned to the signature.
     */
    private String label;


    /**
     * The signature.
     */
    private byte[] signature;


    /**
     * The signature metadata.
     */
    private SignatureMetadata metadata;


    /**
     * Default constructor.
     */
    public SignatureEntry()
    {
    }


    /**
     * Constructor with initial property values.
     *
     * @param label
     *         The label assigned to the signature.
     *
     * @param signature
     *         The signature.
     *
     * @param metadata
     *         The signature metadata.
     */
    public SignatureEntry(String label, byte[] signature, SignatureMetadata metadata)
    {
        this.label     = label;
        this.signature = signature;
        this.metadata  = metadata;
    }


    /**
     * Get the label assigned to the signature.
     *
     * <p>
     * This should be the key of a member in the {@code Signature} and
     * {@code Signature-Input} HTTP fields.
     * </p>
     *
     * @return
     *         The label.
     */
    public String getLabel()
    {
        return label;
    }


    /**
     * Set the label assigned to the signature.
     *
     * <p>
     * This should be the key of a member in the {@code Signature} and
     * {@code Signature-Input} HTTP fields.
     * </p>
     *
     * @param label
     *         The label.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureEntry setLabel(String label)
    {
        this.label = label;

        return this;
    }


    /**
     * Get the signature.
     *
     * <p>
     * This should be the value of a member in the {@code Signature} HTTP
     * field.
     * </p>
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
     * <p>
     * This should be the value of a member in the {@code Signature} HTTP
     * field.
     * </p>
     *
     * @param signature
     *         The signature.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureEntry setSignature(byte[] signature)
    {
        this.signature = signature;

        return this;
    }


    /**
     * Get the signature metadata.
     *
     * <p>
     * This should be the value of a member in the {@code Signature-Input}
     * HTTP field.
     * </p>
     *
     * @return
     *         The signature metadata.
     */
    public SignatureMetadata getMetadata()
    {
        return metadata;
    }


    /**
     * Set the signature metadata.
     *
     * <p>
     * This should be the value of a member in the {@code Signature-Input}
     * HTTP field.
     * </p>
     *
     * @param metadata
     *         The signature metadata.
     *
     * @return
     *         {@code this} object.
     */
    public SignatureEntry setMetadata(SignatureMetadata metadata)
    {
        this.metadata = metadata;

        return this;
    }


    /**
     * Get the string representation of this instance in the following format:
     * <code>"label=<i>{label}</i>, signature=<i>{signature}</i>, metadata=<i>{metadata}</i>"</code>.
     *
     * <p>
     * If the label is set, <code><i>{label}</i></code> is replaced with its
     * value; otherwise, it is an empty string.
     * </p>
     *
     * <p>
     * If the signature is set, <code><i>{signature}</i></code> is replaced
     * with <code>:<i>{base64-encoded-signature}</i>:</code>; otherwise, it
     * is an empty string.
     * </p>
     *
     * <p>
     * If the signature metadata is set, <code><i>{signature}</i></code> is
     * replaced with the result of {@link SignatureMetadata#serialize()};
     * otherwise, it is an empty string.
     * </p>
     *
     * @return
     *         The string representation of this instance.
     */
    @Override
    public String toString()
    {
        return String.format("label=%s, signature=%s, metadata=%s",
                (getLabel()     == null) ? "" : getLabel(),
                (getSignature() == null) ? "" : ":" + Base64.getEncoder().encodeToString(getSignature()) + ":",
                (getMetadata()  == null) ? "" : getMetadata().serialize());
    }


    /**
     * Build a list of signature entries from the provided {@code Signature}
     * and {@code Signature-Input} HTTP fields.
     *
     * <p>
     * This method is an alias of {@link #scan(SignatureField, SignatureInputField, String)
     * scan}{@code (signatureField, signatureInputField, null)}.
     * </p>
     *
     * @param signatureField
     *         A {@link SignatureField} instance that represents the value of
     *         the {@code Signature} HTTP field.
     *
     * @param signatureInputField
     *         A {@link SignatureInputField} instance that represents the value
     *         of the {@code Signature-Input} HTTP field.
     *
     * @return
     *         A map of signature entries, whose keys are signature labels
     *         and values are signature entries.
     *
     * @throws IllegalArgumentException
     *         Input data are invalid.
     */
    public static Map<String, SignatureEntry> scan(
            SignatureField signatureField,
            SignatureInputField signatureInputField) throws IllegalArgumentException
    {
        return scan(signatureField, signatureInputField, null);
    }


    /**
     * Build a list of signature entries from the provided {@code Signature}
     * and {@code Signature-Input} HTTP fields.
     *
     * <p>
     * If both the {@code signatureField} and the {@code signatureInputField}
     * are {@code null}, this method returns {@code null}.
     * </p>
     *
     * <p>
     * If either of the {@code signatureField} or the {@code signatureInputField}
     * is {@code null} but the other is not {@code null}, this method throws an
     * exception.
     * </p>
     *
     * <p>
     * If both the {@code signatureField} and the {@code signatureInputField} are
     * non-null, but the number of members in the {@code signatureInputField} does
     * not match the number of members in the {@code signatureField}, this method
     * throws an exception.
     * </p>
     *
     * <p>
     * If the {@code signatureInputField} does not contain a label found in the
     * {@code signatureField}, this method throws an exception.
     * </p>
     *
     * <p>
     * In other cases, that is, if both the {@code signatureField} and the
     * {@code signatureInputField} are non-null, their numbers of members are
     * equal, and all the labels in the {@code signatureField} are present in
     * the {@code signatureInputField}, this method builds a list of signature
     * entries from the contents of the {@code signatureField} and the
     * {@code signatureInputField}.
     * </p>
     *
     * @param signatureField
     *         A {@link SignatureField} instance that represents the value of
     *         the {@code Signature} HTTP field.
     *
     * @param signatureInputField
     *         A {@link SignatureInputField} instance that represents the value
     *         of the {@code Signature-Input} HTTP field.
     *
     * @param tag
     *         A tag value for filtering. If a non-null value is specified,
     *         only signatures with the tag value are included in the result.
     *
     * @return
     *         A map of signature entries, whose keys are signature labels
     *         and values are signature entries.
     *
     * @throws IllegalArgumentException
     *         Input data are invalid.
     */
    public static Map<String, SignatureEntry> scan(
            SignatureField signatureField,
            SignatureInputField signatureInputField, String tag) throws IllegalArgumentException
    {
        if (signatureField == null)
        {
            if (signatureInputField == null)
            {
                return null;
            }

            // The 'Signature' HTTP field is missing.
            throw exception(
                    "The 'Signature-Input' HTTP field is present, but the " +
                    "corresponding 'Signature' HTTP field is missing.");
        }
        else if (signatureInputField == null)
        {
            // The 'Signature-Input' HTTP field is missing.
            throw exception(
                    "The 'Signature' HTTP field is present, but the " +
                    "corresponding 'Signature-Input' HTTP field is missing.");
        }

        if (signatureField.size() != signatureInputField.size())
        {
            throw exception(
                    "The number of members in the 'Signature-Input' HTTP field " +
                    "does not match the number of members in the 'Signature' " +
                    "HTTP field.");
        }

        // Mappings between label and signature entry.
        Map<String, SignatureEntry> entries = new LinkedHashMap<>(signatureField.size());

        signatureField.forEach((label, signature) -> {
            SignatureMetadata metadata = signatureInputField.get(label);

            if (metadata == null)
            {
                // The 'Signature-Input' HTTP field does not contain the label.
                throw exception(
                        "The 'Signature-Input' HTTP field does not contain " +
                        "a member with the label '%s'.", label);
            }

            // If the 'tag' argument is not specified, or if the specified tag
            // matches the tag of the signature metadata.
            if (tag == null || Objects.equals(tag, extractTag(label, metadata)))
            {
                // label -> signature entry
                entries.put(label, new SignatureEntry(label, signature, metadata));
            }
        });

        return entries;
    }


    private static String extractTag(String label, SignatureMetadata metadata)
    {
        try
        {
            // Get the tag value. If the value is not a string, the getTag()
            // method throws an IllegalStateException.
            return metadata.getParameters().getTag();
        }
        catch (Exception cause)
        {
            throw exception(
                    "The tag of the signature metadata labeled '%s' is malformed: %s",
                    label, cause.getMessage());
        }
    }


    private static IllegalArgumentException exception(String format, Object... args)
    {
        return new IllegalArgumentException(String.format(format, args));
    }
}
