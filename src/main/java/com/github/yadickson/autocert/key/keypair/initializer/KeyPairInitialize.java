/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.keypair.initializer;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;

/**
 *
 * @author Yadickson Soto
 */
public interface KeyPairInitialize {

    void execute(KeyPairGenerator keyPairGenerator, Integer keySize) throws InvalidAlgorithmParameterException;
}
