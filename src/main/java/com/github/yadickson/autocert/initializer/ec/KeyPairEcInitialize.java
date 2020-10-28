/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.initializer.ec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import com.github.yadickson.autocert.initializer.KeyPairInitialize;

/**
 *
 * @author Yadickson Soto
 */
public final class KeyPairEcInitialize implements KeyPairInitialize {

    @Override
    public void execute(final KeyPairGenerator keyPairGenerator, final Integer keySize) throws InvalidAlgorithmParameterException {
        keyPairGenerator.initialize(new ECGenParameterSpec("secp" + keySize + "r1"));
    }
}
