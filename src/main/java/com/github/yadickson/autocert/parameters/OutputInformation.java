/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.parameters;

/**
 *
 * @author Yadickson Soto
 */
public class OutputInformation {

    private String pubFilename;
    private String keyFilename;
    private String certFilename;
    private String directoryName;
    private String outputDirectory;

    public String getPubFilename() {
        return pubFilename;
    }

    public OutputInformation pubFilename(String pubFilename) {
        this.pubFilename = pubFilename;
        return this;
    }

    public String getKeyFilename() {
        return keyFilename;
    }

    public OutputInformation keyFilename(String keyFilename) {
        this.keyFilename = keyFilename;
        return this;
    }

    public String getCertFilename() {
        return certFilename;
    }

    public OutputInformation certFilename(String certFilename) {
        this.certFilename = certFilename;
        return this;
    }

    public String getDirectoryName() {
        return directoryName;
    }

    public OutputInformation directoryName(String directoryName) {
        this.directoryName = directoryName;
        return this;
    }

    public String getOutputDirectory() {
        return outputDirectory;
    }

    public OutputInformation outputDirectory(String outputDirectory) {
        this.outputDirectory = outputDirectory;
        return this;
    }

}
