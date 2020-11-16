/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.keypair.initializer;

import java.util.function.Function;

import javax.inject.Named;

import com.github.yadickson.autocert.key.keypair.initializer.ec.KeyPairEcInitialize;
import com.github.yadickson.autocert.key.keypair.initializer.rsa.KeyPairRsaInitialize;
import com.github.yadickson.autocert.key.algorithm.Algorithm;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class KeyPairInitializeFactory implements Function<Algorithm, KeyPairInitialize>{

    @Override
    public KeyPairInitialize apply(final Algorithm algorithm) {

        switch (algorithm) {
            case RSA:
                return new KeyPairRsaInitialize();
            case EC:
            case ECDSA:
            case ECDH:
                return new KeyPairEcInitialize();
            default:
                throw new KeyPairInitializeNotSupportException(algorithm.name());
        }
    }

}
