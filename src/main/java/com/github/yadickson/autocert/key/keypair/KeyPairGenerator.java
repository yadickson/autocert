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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.github.yadickson.autocert.Parameters;
import com.github.yadickson.autocert.key.algorithm.Algorithm;
import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.provider.Provider;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class KeyPairGenerator {

    private final AlgorithmMapper algorithmMapper;
    private final KeyPairInitializeFactory initializeFactory;

    @Inject
    public KeyPairGenerator(
            final AlgorithmMapper algorithmMapper,
            final KeyPairInitializeFactory initializeFactory
    ) {
        this.algorithmMapper = algorithmMapper;
        this.initializeFactory = initializeFactory;
    }

    public KeyPair execute(
            final Provider provider,
            final Parameters parameters
    ) {

        try {

            final Algorithm algorithm;
            final java.security.KeyPairGenerator keyPairGenerator;
            final KeyPairInitialize initializer;

            algorithm = algorithmMapper.apply(parameters.getAlgorithm());

            keyPairGenerator = java.security.KeyPairGenerator.getInstance(
                    algorithm.getMessage(),
                    provider.getName()
            );

            initializer = initializeFactory.apply(algorithm);
            initializer.execute(keyPairGenerator, parameters.getKeySize());

            return keyPairGenerator.generateKeyPair();

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | RuntimeException ex) {
            throw new KeyPairGeneratorException(ex);
        }
    }

}
