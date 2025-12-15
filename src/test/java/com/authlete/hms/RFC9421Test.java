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


import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.authlete.hms.impl.JoseHttpVerifier;
import com.nimbusds.jose.jwk.JWK;


public class RFC9421Test
{
    /**
     * Example ECC P-256 Test Key from <a href=
     * "https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.1.3"
     * >B&#x2E;1&#x2E;3&#x2E; Example ECC P-256 Test Key</a> of <a href=
     * "https://www.rfc-editor.org/rfc/rfc9421.html">RFC 9421</a>.
     *
     * <p>
     * NOTE: The {@code "alg"} parameter is added for {@link JoseHttpVerifier}.
     * </p>
     */
    private static final String TEST_KEY_ECC_P256 =
            "{\n" +
            "  \"kty\": \"EC\",\n" +
            "  \"alg\": \"ES256\",\n" +
            "  \"crv\": \"P-256\",\n" +
            "  \"kid\": \"test-key-ecc-p256\",\n" +
            "  \"d\": \"UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs\",\n" +
            "  \"x\": \"qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA\",\n" +
            "  \"y\": \"Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0\"\n" +
            "}";


    /**
     * The signature context that provides component values of the
     * {@code test-response} listed in <a href=
     * "https://www.rfc-editor.org/rfc/rfc9421.html#appendix-B.2"
     * >B&#x2E;2&#x2E; Test Cases</a> of <a href=
     * "https://www.rfc-editor.org/rfc/rfc9421.html">RFC 9421</a>.
     *
     * <pre>
     * HTTP/1.1 200 OK
     * Date: Tue, 20 Apr 2021 02:07:56 GMT
     * Content-Type: application/json
     * Content-Digest: sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41Q\
     *   JgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
     * Content-Length: 23
     *
     * {"message": "good dog"}
     * </pre>
     */
    private static class ResponseSignatureContext extends ComponentValueProvider
    {
        ResponseSignatureContext()
        {
            setStatus(200);
            setHeaders(buildHeaders());
        }


        private static Map<String, List<String>> buildHeaders()
        {
            Map<String, List<String>> headers = new LinkedHashMap<>();

            headers.put("Date",           listOf("Tue, 20 Apr 2021 02:07:56 GMT"));
            headers.put("Content-Type",   listOf("application/json"));
            headers.put("Content-Digest", listOf("sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"));
            headers.put("Content-Length", listOf("23"));

            return headers;
        }
    }


    @SuppressWarnings("unchecked")
    private static <E> List<E> listOf(E... elements)
    {
        List<E> list = new ArrayList<>(elements.length);

        for (E element : elements)
        {
            list.add(element);
        }

        return list;
    }


    @Test
    public void test_b_2_4() throws SignatureException, ParseException
    {
        // The values of the Signature and Signature-Input fields excerpted from
        // RFC 9421, B.2.4. Signing a Response Using ecdsa-p256-sha256
        String signatureFieldValue =
                "sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK" +
                "ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:";
        String signatureInputFieldValue =
                "sig-b24=(\"@status\" \"content-type\" " +
                "\"content-digest\" \"content-length\");created=1618884473" +
                ";keyid=\"test-key-ecc-p256\"";

        // Parse the Signature and Signature-Input fields.
        SignatureField signatureField =
                SignatureField.parse(signatureFieldValue);
        SignatureInputField signatureInputField =
                SignatureInputField.parse(signatureInputFieldValue);

        // Extract the signature-metadata pair labeled "sig-b24".
        SignatureEntry signatureEntry =
                SignatureEntry.scan(signatureField, signatureInputField).get("sig-b24");

        // Compute the signature base using the test-response context and the metadata.
        SignatureBase signatureBase =
                new SignatureBaseBuilder(new ResponseSignatureContext()).build(signatureEntry.getMetadata());

        // Prepare the verification key.
        JWK verificationKey = JWK.parse(TEST_KEY_ECC_P256).toPublicJWK();

        // Prepare a verifier to verify the signature.
        HttpVerifier verifier = new JoseHttpVerifier(verificationKey);

        // Verify the signature.
        boolean verified = signatureBase.verify(verifier, signatureEntry.getSignature());

        // The verification should pass.
        assertTrue(verified);
    }
}
