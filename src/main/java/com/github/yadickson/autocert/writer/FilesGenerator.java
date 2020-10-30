/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.writer;

import java.io.File;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import com.github.yadickson.autocert.Parameters;
import com.github.yadickson.autocert.key.KeysResponse;
import com.github.yadickson.autocert.writer.certificate.CertificateWriter;
import com.github.yadickson.autocert.writer.privatekey.PrivateKeyWriter;
import com.github.yadickson.autocert.writer.publickey.PublicKeyWriter;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class FilesGenerator {

    private final PrivateKeyWriter privateKeyWriter;
    private final PublicKeyWriter publicKeyWriter;
    private final CertificateWriter certificateWriter;

    private String customDirectory;

    @Inject
    public FilesGenerator(PrivateKeyWriter privateKeyWriter, PublicKeyWriter publicKeyWriter, CertificateWriter certificateWriter) {
        this.privateKeyWriter = privateKeyWriter;
        this.publicKeyWriter = publicKeyWriter;
        this.certificateWriter = certificateWriter;
    }

    public void execute(final Parameters parameters, final KeysResponse keysResponse) {

        try {

            makeCustomDirectory(parameters);
            makePrivateFile(parameters, keysResponse);
            makePublicFile(parameters, keysResponse);
            makeCertificateFile(parameters, keysResponse);

        } catch (RuntimeException ex) {
            throw new FilesGeneratorException(ex);
        }
    }

    private void makeCustomDirectory(final Parameters parameters) {
        customDirectory = parameters.getOutputDirectory() + File.separator + parameters.getDirectoryName() + File.separator;
    }

    private void makePrivateFile(final Parameters parameters, final KeysResponse keysResponse) {
        final String keyFilePath = customDirectory + parameters.getKeyFilename();
        final EncodedKeySpec privateKey = keysResponse.getPrivateKey();
        privateKeyWriter.execute(keyFilePath, privateKey);
    }

    private void makePublicFile(final Parameters parameters, final KeysResponse keysResponse) {
        final String pubFilePath = customDirectory + parameters.getPubFilename();
        final EncodedKeySpec publicKey = keysResponse.getPublicKey();
        publicKeyWriter.execute(pubFilePath, publicKey);
    }

    private void makeCertificateFile(final Parameters parameters, final KeysResponse keysResponse) {
        final String certFilePath = customDirectory + parameters.getCertFilename();
        final Certificate certificate = keysResponse.getCertificate();
        certificateWriter.execute(certFilePath, certificate);
    }

}
