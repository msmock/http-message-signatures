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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.net.URI;
import java.security.SignatureException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.SignatureInfo;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.nimbusds.jose.jwk.JWK;


public class FapiResourceRequestTest
{
    private static final String SIGNING_KEY =
            "{\n" +
            "  \"kty\": \"EC\",\n" +
            "  \"alg\": \"ES256\",\n" +
            "  \"crv\": \"P-256\",\n" +
            "  \"x\": \"R-z3wlMAAQ73arr3JkxfP04woVLm1zHJXX2IGCm7z5c\",\n" +
            "  \"y\": \"zs5TKDbreY-5rUqx1xiMc1aKP9CWq3dL6wZJ3wVTf50\",\n" +
            "  \"d\": \"E67QqVgry3Y7vlMyuEID4CRbubQON9Bf-PLaB3lIdFs\",\n" +
            "  \"kid\": \"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\",\n" +
            "  \"use\": \"sig\"\n" +
            "}";

    // The HTTP method.
    private static final String HTTP_METHOD = "POST";

    // The target URI.
    private static final URI TARGET_URI = URI.create("https://example.com/path?key=value");

    // The value of the Authorization HTTP header.
    private static final String AUTHORIZATION = "Bearer abc";

    // The content-digest value for testing; sha-256 of "{}".
    private static final String CONTENT_DIGEST =
            "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:";


    private static void sleep(long milliseconds)
    {
        try
        {
            Thread.sleep(milliseconds);
        }
        catch (InterruptedException cause)
        {
            cause.printStackTrace();
        }
    }


    @Test
    public void test_default_metadata() throws ParseException, IllegalStateException, SignatureException
    {
        JWK signingKey      = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created     = Instant.now();

        // Create a signer.
        FapiResourceRequestSigner signer = createSigner(created, signingKey);

        // Sign
        SignatureInfo info = signer.sign();

        // Check the signature metadata.
        checkDefaultMetadata(created, info);

        // Check the signature serialization.
        checkSerialization(info);

        // Create a verifier.
        FapiResourceRequestVerifier verifier = createVerifier(verificationKey);

        // Sleep 1 second to make Instant.now() generate a different value than 'created'.
        sleep(1000);

        // Verify with the default signature metadata. This verification should fail.
        boolean verified = verifier.verify(info.getSignature(), null);
        assertFalse(verified, "Signature verification unexpectedly passed.");

        // Let the verifier use the 'created' value when it builds the default
        // signature metadata.
        verifier.setCreated(created);

        // Verify with the default signature metadata. This verification should pass.
        verified = verifier.verify(info.getSignature(), null);
        assertTrue(verified, "Signature verification unexpectedly failed.");

        // Verify with the same signature metadata as used for signing.
        // This verification should pass.
        verified = verifier.verify(info.getSignature(), info.getMetadata());
        assertTrue(verified, "Signature verification unexpectedly failed.");
    }


    private static FapiResourceRequestSigner createSigner(Instant created, JWK signingKey)
    {
        return new FapiResourceRequestSigner()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setCreated(created)
                .setSigningKey(signingKey)
                ;
    }


    private static FapiResourceRequestVerifier createVerifier(JWK verificationKey)
    {
        return new FapiResourceRequestVerifier()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setContentDigest(CONTENT_DIGEST)
                .setVerificationKey(verificationKey)
                ;
    }


    private static void checkDefaultMetadata(Instant created, SignatureInfo info)
    {
        // Expected signature metadata
        String expectedMetadata = String.format(
                "(\"@method\" \"@target-uri\" \"authorization\" \"content-digest\")" +
                ";created=%d;keyid=\"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\"" +
                ";tag=\"fapi-2-request\"", created.getEpochSecond());

        // Actual signature metadata
        String actualMetadata = info.getSerializedSignatureMetadata();

        assertEquals(expectedMetadata, actualMetadata);
    }


    private static void checkSerialization(SignatureInfo info)
    {
        // Expected signature serialization
        String expectedSerializedSignature = String.format(":%s:",
                Base64.getEncoder().encodeToString(info.getSignature()));

        // Actual signature serialization
        String actualSerializedSignature = info.getSerializedSignature();

        assertEquals(expectedSerializedSignature, actualSerializedSignature);
    }


    @Test
    public void test_custom_metadata() throws ParseException, IllegalStateException, SignatureException
    {
        JWK signingKey      = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created     = Instant.now();

        // Create a signer.
        FapiResourceRequestSigner signer = createSigner(created, signingKey);

        // Custom metadata with a different order of component identifiers
        // and a different order of parameters.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("authorization"),
                        new ComponentIdentifier("@target-uri"),
                        new ComponentIdentifier("content-digest"),
                        new ComponentIdentifier("@method")
                ),
                new SignatureMetadataParameters().setTag("fapi-2-request").setCreated(created)
                );

        // Sign
        SignatureInfo info = signer.sign(metadata);

        // Check the signature metadata.
        checkCustomMetadata(created, info);

        // Create a verifier.
        FapiResourceRequestVerifier verifier = createVerifier(verificationKey);

        // Verify with the custom metadata. This verification should pass.
        boolean verified = verifier.verify(info.getSignature(), metadata);
        assertTrue(verified, "Signature verification unexpectedly failed.");

        // Verify with the default metadata. This verification should fail.
        verifier.setCreated(created);
        verified = verifier.verify(info.getSignature(), null);
        assertFalse(verified, "Signature verification unexpectedly passed.");
    }


    private static void checkCustomMetadata(Instant created, SignatureInfo info)
    {
        // Expected signature metadata
        String expectedMetadata = String.format(
                "(\"authorization\" \"@target-uri\" \"content-digest\" \"@method\")" +
                ";tag=\"fapi-2-request\";created=%d", created.getEpochSecond());

        // Actual signature metadata
        String actualMetadata = info.getSerializedSignatureMetadata();

        assertEquals(expectedMetadata, actualMetadata);
    }
}
