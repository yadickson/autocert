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

import com.github.yadickson.autocert.key.KeysResponse;
import com.github.yadickson.autocert.parameters.OutputInformation;
import com.github.yadickson.autocert.parameters.Parameters;
import com.github.yadickson.autocert.writer.certificate.CertificateWriter;
import com.github.yadickson.autocert.writer.privatekey.PrivateKeyWriter;
import com.github.yadickson.autocert.writer.publickey.PublicKeyWriter;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class FilesGenerator {

    private final PrivateKeyWriter privateKeyWriter;
    private final PublicKeyWriter publicKeyWriter;
    private final CertificateWriter certificateWriter;

    private OutputInformation outputInformation;
    private String customDirectory;

    @Inject
    public FilesGenerator(PrivateKeyWriter privateKeyWriter, PublicKeyWriter publicKeyWriter, CertificateWriter certificateWriter) {
        this.privateKeyWriter = privateKeyWriter;
        this.publicKeyWriter = publicKeyWriter;
        this.certificateWriter = certificateWriter;
    }

    public void execute(final Parameters parameters, final KeysResponse keysResponse) {

        try {

            setOutputInformation(parameters);
            makeCustomDirectory();
            makePrivateFile(keysResponse);
            makePublicFile(keysResponse);
            makeCertificateFile(keysResponse);

        } catch (RuntimeException ex) {
            throw new FilesGeneratorException(ex);
        }
    }

    private void setOutputInformation(Parameters parameters) {
        this.outputInformation = parameters.getOutput();
    }

    private void makeCustomDirectory() {
        customDirectory = outputInformation.getOutputDirectory() + File.separator + outputInformation.getDirectoryName() + File.separator;
    }

    private void makePrivateFile(final KeysResponse keysResponse) {
        final String keyFilePath = customDirectory + outputInformation.getKeyFilename();
        final EncodedKeySpec privateKey = keysResponse.getPrivateKey();
        privateKeyWriter.execute(keyFilePath, privateKey);
    }

    private void makePublicFile(final KeysResponse keysResponse) {
        final String pubFilePath = customDirectory + outputInformation.getPubFilename();
        final EncodedKeySpec publicKey = keysResponse.getPublicKey();
        publicKeyWriter.execute(pubFilePath, publicKey);
    }

    private void makeCertificateFile(final KeysResponse keysResponse) {
        final String certFilePath = customDirectory + outputInformation.getCertFilename();
        final Certificate certificate = keysResponse.getCertificate();
        certificateWriter.execute(certFilePath, certificate);
    }

}
