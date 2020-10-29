/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.keypair.initializer.rsa;

import java.security.KeyPairGenerator;

import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitialize;

/**
 *
 * @author Yadickson Soto
 */
public final class KeyPairRsaInitialize implements KeyPairInitialize {
    
    @Override
    public void execute(final KeyPairGenerator keyPairGenerator, final Integer keySize) {
        keyPairGenerator.initialize(keySize);
    }
}
