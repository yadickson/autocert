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
public class InputInformation {

    private String algorithm;
    private Integer keySize;
    private String signature;
    private Integer years;
    private String issuer;
    private String subject;

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

    public static class Builder {

        private final InputInformation information = new InputInformation();

        public Builder algorithm(String algorithm) {
            information.algorithm = algorithm;
            return this;
        }

        public Builder keySize(Integer keySize) {
            information.keySize = keySize;
            return this;
        }

        public Builder signature(String signature) {
            information.signature = signature;
            return this;
        }

        public Builder years(Integer years) {
            information.years = years;
            return this;
        }

        public Builder issuer(String issuer) {
            information.issuer = issuer;
            return this;
        }

        public Builder subject(String subject) {
            information.subject = subject;
            return this;
        }

        public InputInformation build() {
            return information;
        }
    }
}
