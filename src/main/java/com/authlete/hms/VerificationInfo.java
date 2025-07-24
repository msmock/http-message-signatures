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


import com.nimbusds.jose.jwk.JWK;


/**
 * Information about verification operation, including the computed signature
 * base and the verification result.
 *
 * @since 1.5
 */
public class VerificationInfo extends SignatureOperationInfo<VerificationInfo>
{
    /**
     * The verification key used in the verification operation.
     */
    private JWK verificationKey;


    /**
     * The result of the verification operation.
     */
    private boolean verified;


    /**
     * The reason of the verification result.
     */
    private String reason;


    /**
     * Get the verification key used in the verification operation.
     *
     * @return
     *         The verification key.
     */
    public JWK getVerificationKey()
    {
        return verificationKey;
    }


    /**
     * Set the verification key used in the verification operation.
     *
     * @param key
     *         The verification key.
     *
     * @return
     *         {@code this} object.
     */
    public VerificationInfo setVerificationKey(JWK key)
    {
        this.verificationKey = key;

        return this;
    }


    /**
     * Get the result of the verification operation.
     *
     * @return
     *         The result of the verification operation.
     */
    public boolean isVerified()
    {
        return verified;
    }


    /**
     * Set the result of the verification operation.
     *
     * @param verified
     *         The result of the verification operation.
     *
     * @return
     *         {@code this} object.
     */
    public VerificationInfo setVerified(boolean verified)
    {
        this.verified = verified;

        return this;
    }


    /**
     * Get the reason of the verification result.
     *
     * @return
     *         The reason of the verification result.
     */
    public String getReason()
    {
        return reason;
    }


    /**
     * Set the reason of the verification result.
     *
     * @param reason
     *         The reason of the verification result.
     *
     * @return
     *         {@code this} object.
     */
    public VerificationInfo setReason(String reason)
    {
        this.reason = reason;

        return this;
    }
}
