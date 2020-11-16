/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.privatekey;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.inject.Named;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class PrivateKeyGenerator {

    public EncodedKeySpec execute(final KeyPair keyPair) {
        final PrivateKey privateKey = keyPair.getPrivate();
        final byte[] encode = privateKey.getEncoded();
        return new PKCS8EncodedKeySpec(encode);
    }
}
