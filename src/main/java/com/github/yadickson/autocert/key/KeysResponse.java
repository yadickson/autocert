/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key;

import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;

/**
 *
 * @author Yadickson Soto
 */
public class KeysResponse {

    private final EncodedKeySpec privateKey;
    private final EncodedKeySpec publicKey;
    private final Certificate certificate;

    public KeysResponse(EncodedKeySpec privateKey, EncodedKeySpec publicKey, Certificate certificate) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.certificate = certificate;
    }

    public EncodedKeySpec getPrivateKey() {
        return privateKey;
    }

    public EncodedKeySpec getPublicKey() {
        return publicKey;
    }

    public Certificate getCertificate() {
        return certificate;
    }

}
