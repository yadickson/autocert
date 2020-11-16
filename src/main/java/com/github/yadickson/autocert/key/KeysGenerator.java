/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;

import javax.inject.Inject;
import javax.inject.Named;

import com.github.yadickson.autocert.parameters.Parameters;
import com.github.yadickson.autocert.key.certificate.CertificateGenerator;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.privatekey.PrivateKeyGenerator;
import com.github.yadickson.autocert.key.provider.ProviderDecorator;
import com.github.yadickson.autocert.key.publickey.PublicKeyGenerator;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class KeysGenerator {

    private final KeyPairGenerator keyPairGenerator;
    private final PrivateKeyGenerator privateKeyGenerator;
    private final PublicKeyGenerator publicKeyGenerator;
    private final CertificateGenerator certificateGenerator;

    @Inject
    public KeysGenerator(KeyPairGenerator keyPairGenerator, PrivateKeyGenerator privateKeyGenerator, PublicKeyGenerator publicKeyGenerator, CertificateGenerator certificateGenerator) {
        this.keyPairGenerator = keyPairGenerator;
        this.privateKeyGenerator = privateKeyGenerator;
        this.publicKeyGenerator = publicKeyGenerator;
        this.certificateGenerator = certificateGenerator;
    }

    public KeysResponse execute(final Parameters parameters) {
        try (ProviderDecorator provider = new ProviderDecorator()) {

            final KeyPair keyPair;
            final EncodedKeySpec privateKey;
            final EncodedKeySpec publicKey;
            final Certificate certificate;

            keyPair = keyPairGenerator.execute(parameters, provider);
            privateKey = privateKeyGenerator.execute(keyPair);
            publicKey = publicKeyGenerator.execute(keyPair);
            certificate = certificateGenerator.execute(parameters, provider, keyPair);

            return new KeysResponse(privateKey, publicKey, certificate);

        } catch (IOException | RuntimeException ex) {
            throw new KeysGeneratorException(ex);
        }
    }
}
