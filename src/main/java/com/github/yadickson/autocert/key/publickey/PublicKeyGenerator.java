/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.publickey;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.inject.Named;
import javax.inject.Singleton;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class PublicKeyGenerator {

    public EncodedKeySpec execute(final KeyPair keyPair) {
        final PublicKey publicKey = keyPair.getPublic();
        final byte[] encode = publicKey.getEncoded();
        return new X509EncodedKeySpec(encode);
    }
}
