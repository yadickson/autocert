/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.secrectkey;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.github.yadickson.autocert.key.algorithm.Algorithm;
import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.provider.Provider;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class SecretKeyGenerator {

    private final AlgorithmMapper algorithmMapper;
    
    @Inject
    public SecretKeyGenerator(final AlgorithmMapper algorithmMapper) {
        this.algorithmMapper = algorithmMapper;
    }
    
    public SecretKey execute(
            final Provider provider,
            final KeyPair keyPair
    ) {

        try {

            final String type;
            final PrivateKey privateKey = keyPair.getPrivate();
            final PublicKey publicKey = keyPair.getPublic();

            type = getKeyAgreementType(privateKey);

            KeyAgreement ka = KeyAgreement.getInstance(type, provider.getName());

            ka.init(privateKey);
            ka.doPhase(publicKey, true);

            return ka.generateSecret("AES");

        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | RuntimeException ex) {
            throw new SecretKeyGeneratorException(ex);
        }
    }

    private String getKeyAgreementType(final PrivateKey privateKey) {

        Algorithm algorithm = algorithmMapper.apply(privateKey.getAlgorithm());

        switch (algorithm) {
            case EC:
            case ECDSA:
            case ECDH:
                return "ECDH";
            default:
                throw new SecretKeyAlgorithmGeneratorException("The algorithm " + algorithm + " not supported");
        }
    }

}
