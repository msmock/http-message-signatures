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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;


public class SignatureEntryTest
{
    private static Map<String, SignatureEntry> scan(
            String signatureField, String signatureInputField, boolean exceptionExpected)
    {
        try
        {
            return scan(
                    SignatureField.parse(signatureField),
                    SignatureInputField.parse(signatureInputField),
                    exceptionExpected);
        }
        catch (SignatureException cause)
        {
            cause.printStackTrace();

            fail(cause.getMessage());

            return null;
        }
    }


    private static Map<String, SignatureEntry> scan(
            SignatureField signatureField, SignatureInputField signatureInputField,
            boolean exceptionExpected)
    {
        if (exceptionExpected)
        {
            assertThrows(IllegalArgumentException.class,
                    () -> SignatureEntry.scan(signatureField, signatureInputField));
            return null;
        }
        else
        {
            return SignatureEntry.scan(signatureField, signatureInputField);
        }
    }


    private static String toBase64(byte[] input)
    {
        return Base64.getEncoder().encodeToString(input);
    }


    @Test
    public void test_both_null()
    {
        scan((SignatureField)null, null, false);
    }


    @Test
    public void test_null_nonnull()
    {
        scan(null, new SignatureInputField(), true);
    }


    @Test
    public void test_nonnull_null()
    {
        scan(new SignatureField(), null, true);
    }


    @Test
    public void test_different_size()
    {
        scan("a=:YQ==:, b=:Yg==:", "a=()", true);
    }


    @Test
    public void test_different_label()
    {
        scan("a=:YQ==:, b=:Yg==:", "a=(), c=()", true);
    }


    @Test
    public void test_normal()
    {
        Map<String, SignatureEntry> entries = scan("a=:YQ==:, b=:Yg==:", "a=(), b=()", false);

        assertNotNull(entries);
        assertEquals(2, entries.size());

        SignatureEntry a = entries.get("a");
        assertNotNull(a);
        assertEquals("a", a.getLabel());
        assertEquals("YQ==", toBase64(a.getSignature()));

        SignatureEntry b = entries.get("b");
        assertNotNull(b);
        assertEquals("b", b.getLabel());
        assertEquals("Yg==", toBase64(b.getSignature()));
    }


    @Test
    public void test_string()
    {
        SignatureEntry signatureEntry = scan("a=:YQ==:", "a=()", false).get("a");

        String expected = "label=a, signature=:YQ==:, metadata=()";
        String actual   = signatureEntry.toString();

        assertEquals(expected, actual);
    }
}
