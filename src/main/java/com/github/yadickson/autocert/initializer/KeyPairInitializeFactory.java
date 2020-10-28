/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.initializer;

import java.util.function.Function;

import javax.inject.Named;
import javax.inject.Singleton;

import com.github.yadickson.autocert.initializer.ec.KeyPairEcInitialize;
import com.github.yadickson.autocert.initializer.rsa.KeyPairRsaInitialize;
import com.github.yadickson.autocert.model.Algorithm;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
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
                throw new KeyPairInitializeNotSupportException(algorithm.getMessage());
        }
    }

}
