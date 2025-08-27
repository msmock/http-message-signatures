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
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentIdentifierParameters;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.SigningInfo;
import com.authlete.hms.VerificationInfo;
import com.nimbusds.jose.jwk.JWK;


public class FapiResourceResponseTest
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

    // The value of the Authorization header.
    private static final String AUTHORIZATION = "Bearer abc";

    // The HTTP status.
    private static final int STATUS = 200;

    // The "content-digest";req value for testing; sha-256 of "{}".
    private static final String REQUEST_CONTENT_DIGEST =
            "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:";

    // The "content-digest" value for testing; sha-256 of "{\"hello\": \"world\"}".
    private static final String RESPONSE_CONTENT_DIGEST =
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";


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
        FapiResourceResponseSigner signer = createSigner(created, signingKey);

        // Sign
        SigningInfo sinfo = signer.sign();

        // Check the signature metadata.
        checkDefaultMetadata(created, sinfo);

        // Check the signature serialization.
        checkSerialization(sinfo);

        // Create a verifier.
        FapiResourceResponseVerifier verifier = createVerifier(verificationKey);

        // Sleep 1 second to make Instant.now() generate a different value than 'created'.
        sleep(1000);

        // Verify with the default signature metadata. This verification should fail.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), null);
        assertFalse(vinfo.isVerified(), "Signature verification unexpectedly passed.");

        // Let the verifier use the 'created' value when it builds the default
        // signature metadata.
        verifier.setCreated(created);

        // Verify with the default signature metadata. This verification should pass.
        vinfo = verifier.verify(sinfo.getSignature(), null);
        assertTrue(vinfo.isVerified(), "Signature verification unexpectedly failed.");

        // Verify with the same signature metadata as used for signing.
        // This verification should pass.
        vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertTrue(vinfo.isVerified(), "Signature verification unexpectedly failed.");
    }


    private static FapiResourceResponseSigner createSigner(Instant created, JWK signingKey)
    {
        return new FapiResourceResponseSigner()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setRequestContentDigest(REQUEST_CONTENT_DIGEST)
                .setStatus(STATUS)
                .setResponseContentDigest(RESPONSE_CONTENT_DIGEST)
                .setCreated(created)
                .setSigningKey(signingKey)
                ;
    }


    private static FapiResourceResponseVerifier createVerifier(JWK verificationKey)
    {
        return new FapiResourceResponseVerifier()
                .setMethod(HTTP_METHOD)
                .setTargetUri(TARGET_URI)
                .setAuthorization(AUTHORIZATION)
                .setRequestContentDigest(REQUEST_CONTENT_DIGEST)
                .setStatus(STATUS)
                .setResponseContentDigest(RESPONSE_CONTENT_DIGEST)
                .setVerificationKey(verificationKey)
                ;
    }


    private static void checkDefaultMetadata(Instant created, SigningInfo info)
    {
        // Expected signature metadata
        String expectedMetadata = String.format(
                "(\"@method\";req \"@target-uri\";req \"authorization\";req " +
                "\"content-digest\";req \"@status\" \"content-digest\")" +
                ";created=%d;keyid=\"snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio\"" +
                ";tag=\"fapi-2-response\"", created.getEpochSecond());

        // Actual signature metadata
        String actualMetadata = info.getSerializedSignatureMetadata();

        assertEquals(expectedMetadata, actualMetadata);
    }


    private static void checkSerialization(SigningInfo info)
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
        FapiResourceResponseSigner signer = createSigner(created, signingKey);

        // ;req
        ComponentIdentifierParameters req = new ComponentIdentifierParameters().setReq(true);

        // Custom metadata with a different order of component identifiers
        // and a different order of parameters.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("@status"),
                        new ComponentIdentifier("content-digest"),
                        new ComponentIdentifier("@target-uri", req),
                        new ComponentIdentifier("content-digest", req),
                        new ComponentIdentifier("authorization", req),
                        new ComponentIdentifier("@method", req)
                ),
                new SignatureMetadataParameters().setTag("fapi-2-response").setCreated(created)
                );

        // Sign
        SigningInfo sinfo = signer.sign(metadata);

        // Check the signature metadata.
        checkCustomMetadata(created, sinfo);

        // Create a verifier.
        FapiResourceResponseVerifier verifier = createVerifier(verificationKey);

        // Verify with the custom metadata. This verification should pass.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), metadata);
        assertTrue(vinfo.isVerified(), "Signature verification unexpectedly failed.");

        // Verify with the default metadata. This verification should fail.
        verifier.setCreated(created);
        vinfo = verifier.verify(sinfo.getSignature(), null);
        assertFalse(vinfo.isVerified(), "Signature verification unexpectedly passed.");
    }


    private static void checkCustomMetadata(Instant created, SigningInfo info)
    {
        // Expected signature metadata
        String expectedMetadata = String.format(
                "(\"@status\" \"content-digest\" \"@target-uri\";req " +
                "\"content-digest\";req \"authorization\";req \"@method\";req)" +
                ";tag=\"fapi-2-response\";created=%d", created.getEpochSecond());

        // Actual signature metadata
        String actualMetadata = info.getSerializedSignatureMetadata();

        assertEquals(expectedMetadata, actualMetadata);
    }


    @Test
    public void test_missing_component() throws ParseException, IllegalStateException, SignatureException
    {
        JWK signingKey      = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created     = Instant.now();

        // Create a signer.
        FapiResourceResponseSigner signer = createSigner(created, signingKey);

        // ;req
        ComponentIdentifierParameters req = new ComponentIdentifierParameters().setReq(true);

        // Signature metadata that is missing mandatory components.
        SignatureMetadata metadata = new SignatureMetadata(
                // "@target-uri";req is missing.
                Arrays.asList(
                        new ComponentIdentifier("@method", req),
                        new ComponentIdentifier("content-digest", req),
                        new ComponentIdentifier("@status"),
                        new ComponentIdentifier("content-digest")
                ),
                new SignatureMetadataParameters()
                    .setCreated(created)
                    .setTag("fapi-2-response")
        );

        // Sign with the invalid metadata.
        SigningInfo sinfo = signer.sign(metadata);

        // Create a verifier.
        FapiResourceResponseVerifier verifier = createVerifier(verificationKey);

        // Verify with the same signature metadata as used for signing.
        //
        // This verification should fail because the required component
        // "@target-uri";req is missing.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertFalse(vinfo.isVerified(), "Signature verification unexpectedly passed.");
    }


    @Test
    public void test_expired() throws ParseException, IllegalStateException, SignatureException
    {
        JWK signingKey      = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created     = Instant.now();

        // Create a signer.
        FapiResourceResponseSigner signer = createSigner(created, signingKey);

        // ;req
        ComponentIdentifierParameters req = new ComponentIdentifierParameters().setReq(true);

        // Signature metadata with a 'created' parameter set too far in the past,
        // causing the verifier to consider the HTTP message signature expired.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("@method", req),
                        new ComponentIdentifier("@target-uri", req),
                        new ComponentIdentifier("authorization", req),
                        new ComponentIdentifier("content-digest", req),
                        new ComponentIdentifier("@status"),
                        new ComponentIdentifier("content-digest")
                ),
                new SignatureMetadataParameters()
                    .setCreated(created.minus(Duration.ofHours(1)))
                    .setTag("fapi-2-response")
        );

        // Sign with the invalid metadata.
        SigningInfo sinfo = signer.sign(metadata);

        // Create a verifier.
        FapiResourceResponseVerifier verifier = createVerifier(verificationKey);

        // Verify with the same signature metadata as used for signing.
        //
        // This verification should fail because the 'created' parameter
        // indicates that the HTTP message signature has expired.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertFalse(vinfo.isVerified(), "Signature verification unexpectedly passed.");
    }


    @Test
    public void test_bad_tag() throws ParseException, IllegalStateException, SignatureException
    {
        JWK signingKey      = JWK.parse(SIGNING_KEY);
        JWK verificationKey = signingKey.toPublicJWK();
        Instant created     = Instant.now();

        // Create a signer.
        FapiResourceResponseSigner signer = createSigner(created, signingKey);

        // ;req
        ComponentIdentifierParameters req = new ComponentIdentifierParameters().setReq(true);

        // Signature metadata whose 'tag' parameter holds an unexpected value.
        SignatureMetadata metadata = new SignatureMetadata(
                Arrays.asList(
                        new ComponentIdentifier("@method", req),
                        new ComponentIdentifier("@target-uri", req),
                        new ComponentIdentifier("authorization", req),
                        new ComponentIdentifier("content-digest", req),
                        new ComponentIdentifier("@status"),
                        new ComponentIdentifier("content-digest")
                ),
                new SignatureMetadataParameters()
                    .setCreated(created)
                    .setTag("unknown")
        );

        // Sign with the invalid metadata.
        SigningInfo sinfo = signer.sign(metadata);

        // Create a verifier.
        FapiResourceResponseVerifier verifier = createVerifier(verificationKey);

        // Verify with the same signature metadata as used for signing.
        //
        // This verification should fail because the 'tag' parameter
        // holds an unexpected value.
        VerificationInfo vinfo = verifier.verify(sinfo.getSignature(), sinfo.getMetadata());
        assertFalse(vinfo.isVerified(), "Signature verification unexpectedly passed.");
    }
}
