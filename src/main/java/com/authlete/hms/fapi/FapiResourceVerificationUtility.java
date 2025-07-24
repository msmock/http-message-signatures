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
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.SignatureMetadata;


final class FapiResourceVerificationUtility
{
    private FapiResourceVerificationUtility()
    {
    }


    public static void checkComponents(
            SignatureMetadata metadata, Collection<ComponentIdentifier> requiredComponents) throws SignatureException
    {
        for (ComponentIdentifier component : requiredComponents)
        {
            if (metadata.contains(component))
            {
                continue;
            }

            throw exception(
                    "The @signature-params is missing the required component '%s'.", component);
        }
    }


    public static void checkParameterCreated(
            SignatureMetadata metadata) throws SignatureException
    {
        // FAPI 2.0 Http Signatures
        //
        //   * shall reject requests with signatures that are missing the
        //     `created` parameter or have a `created` value that is greater
        //     than an acceptable range (1 minute is recommended);
        //

        // FAPI 2.0 Security Profile
        //
        //   NOTE 3: Clock skew is a cause of many interoperability issues.
        //   Even a few hundred milliseconds of clock skew can cause JWTs to
        //   be rejected for being "issued in the future". The DPoP
        //   specification [RFC9449] suggests that JWTs are accepted in the
        //   reasonably near future (on the order of seconds or minutes).
        //   This document goes further by requiring authorization servers
        //   to accept JWTs that have timestamps up to 10 seconds in the
        //   future. 10 seconds was chosen as a value that does not affect
        //   security while greatly increasing interoperability. Implementers
        //   are free to accept JWTs with a timestamp of up to 60 seconds in
        //   the future. Some ecosystems have found that the value of 30
        //   seconds is needed to fully eliminate clock skew issues.
        //   To prevent implementations switching off iat and nbf checks
        //   completely this document imposes a maximum timestamp in the
        //   future of 60 seconds.
        //

        // The value of the 'created' parameter.
        Instant created = metadata.getParameters().getCreated();

        // If the 'created' parameter is missing.
        if (created == null)
        {
            throw exception(
                    "The @signature-params is missing the 'created' parameter.");
        }

        Instant  currentTime    = Instant.now();
        Duration lifetime       = Duration.ofSeconds(60);
        Instant  expirationTime = created.plus(lifetime);
        Duration clockSkew      = Duration.ofSeconds(60);

        // If the current time is before the expiration time.
        if (isBeforeTolerant(currentTime, expirationTime, clockSkew))
        {
            // OK. The HTTP message signature has not expired yet.
            return;
        }

        // The HTTP message signature has expired.
        throw exception(
                "The 'created' parameter of the @signature-params indicates " +
                "that the HTTP message signature has expired - the current " +
                "time '%d' is after the expiration time '%d' (the signature " +
                "creation time '%d' + %d seconds).",
                currentTime.getEpochSecond(), expirationTime.getEpochSecond(),
                created.getEpochSecond(), lifetime.getSeconds());
    }


    public static void checkParameterTag(
            SignatureMetadata metadata, String requiredTag) throws SignatureException
    {
        // The value of the 'tag' parameter.
        String tag = metadata.getParameters().getTag();

        // If the 'tag' parameter is missing.
        if (tag == null)
        {
            throw exception(
                    "The @signature-params is missing the 'tag' parameter.");
        }

        // If the 'tag' value differs from the required value.
        if (!tag.equals(requiredTag))
        {
            throw exception(
                    "The tag of the @signature-params is '%s', but it must be '%s'.",
                    tag, requiredTag);
        }
    }


    private static SignatureException exception(String format, Object... args)
    {
        return new SignatureException(String.format(format, args));
    }


    /**
     * True if the time {@code a} is before the time {@code b}, allowing a tolerance
     * defined by {@code clockSkew}.
     */
    private static boolean isBeforeTolerant(Instant a, Instant b, Duration clockSkew)
    {
        return a.minus(clockSkew).compareTo(b) < 0;
    }
}
