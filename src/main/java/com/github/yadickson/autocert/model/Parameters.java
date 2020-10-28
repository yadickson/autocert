/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.model;

import java.io.File;

/**
 *
 * @author Yadickson Soto
 */
public class Parameters {

    private final String pubFilename;
    private final String keyFilename;
    private final String certFilename;
    private final String algorithm;
    private final Integer keySize;
    private final String signature;
    private final Integer years;
    private final String issuer;
    private final String subject;
    private final String directoryName;
    private final File outputDirectory;

    public Parameters(String pubFilename, String keyFilename, String certFilename, String algorithm, Integer keySize, String signature, Integer years, String issuer, String subject, String directoryName, File outputDirectory) {
        this.pubFilename = pubFilename;
        this.keyFilename = keyFilename;
        this.certFilename = certFilename;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.signature = signature;
        this.years = years;
        this.issuer = issuer;
        this.subject = subject;
        this.directoryName = directoryName;
        this.outputDirectory = outputDirectory;
    }

    public String getPubFilename() {
        return pubFilename;
    }

    public String getKeyFilename() {
        return keyFilename;
    }

    public String getCertFilename() {
        return certFilename;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public String getSignature() {
        return signature;
    }

    public Integer getYears() {
        return years;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public String getDirectoryName() {
        return directoryName;
    }

    public File getOutputDirectory() {
        return outputDirectory;
    }

}
