/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.keypair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.inject.Named;
import javax.inject.Singleton;

import com.github.yadickson.autocert.model.Algorithm;
import com.github.yadickson.autocert.model.Provider;
import com.github.yadickson.autocert.initializer.KeyPairInitialize;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class KeyPairGenerator {

    public KeyPair execute(
            final Provider provider,
            final KeyPairInitialize initializer,
            final Algorithm algorithm,
            final Integer keySize
    ) {

        try {

            final java.security.KeyPairGenerator keyPairGenerator;

            keyPairGenerator = java.security.KeyPairGenerator.getInstance(
                    algorithm.getMessage(),
                    provider.getName()
            );

            initializer.execute(keyPairGenerator, keySize);

            return keyPairGenerator.generateKeyPair();

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | RuntimeException ex) {
            throw new KeyPairGeneratorException(ex);
        }
    }

}
