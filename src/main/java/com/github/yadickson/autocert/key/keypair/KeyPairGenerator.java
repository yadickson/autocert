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

import com.github.yadickson.autocert.key.algorithm.Algorithm;
import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.key.provider.Provider;
import com.github.yadickson.autocert.parameters.InputInformation;
import com.github.yadickson.autocert.parameters.Parameters;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class KeyPairGenerator {

    private final AlgorithmMapper algorithmMapper;
    private final KeyPairInitializeFactory initializeFactory;

    private InputInformation inputInformation;

    @Inject
    public KeyPairGenerator(
            final AlgorithmMapper algorithmMapper,
            final KeyPairInitializeFactory initializeFactory
    ) {
        this.algorithmMapper = algorithmMapper;
        this.initializeFactory = initializeFactory;
    }

    public KeyPair execute(
            final Parameters parameters,
            final Provider provider
    ) {

        try {

            setInputInformation(parameters);
            return createKeyPair(provider);

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | RuntimeException ex) {
            throw new KeyPairGeneratorException(ex);
        }
    }

    private void setInputInformation(final Parameters parameters) {
        this.inputInformation = parameters.getInput();
    }

    private KeyPair createKeyPair(final Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

        final Algorithm algorithm;
        final java.security.KeyPairGenerator keyPairGenerator;
        final KeyPairInitialize initializer;

        algorithm = algorithmMapper.apply(inputInformation.getAlgorithm());

        keyPairGenerator = java.security.KeyPairGenerator.getInstance(
                algorithm.name(),
                provider.getName()
        );

        initializer = initializeFactory.apply(algorithm);
        initializer.execute(keyPairGenerator, inputInformation.getKeySize());

        return keyPairGenerator.generateKeyPair();
    }

}
