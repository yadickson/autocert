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

    public String getKeyFilename() {
        return keyFilename;
    }

    public String getCertFilename() {
        return certFilename;
    }

    public String getDirectoryName() {
        return directoryName;
    }

    public String getOutputDirectory() {
        return outputDirectory;
    }

    public static class Builder {

        private final OutputInformation information = new OutputInformation();

        public Builder pubFilename(String pubFilename) {
            information.pubFilename = pubFilename;
            return this;
        }

        public Builder keyFilename(String keyFilename) {
            information.keyFilename = keyFilename;
            return this;
        }

        public Builder certFilename(String certFilename) {
            information.certFilename = certFilename;
            return this;
        }

        public Builder directoryName(String directoryName) {
            information.directoryName = directoryName;
            return this;
        }

        public Builder outputDirectory(String outputDirectory) {
            information.outputDirectory = outputDirectory;
            return this;
        }

        public OutputInformation build() {
            return information;
        }
    }

}
