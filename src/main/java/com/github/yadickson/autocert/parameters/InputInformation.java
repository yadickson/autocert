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

    public InputInformation algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public InputInformation keySize(Integer keySize) {
        this.keySize = keySize;
        return this;
    }

    public String getSignature() {
        return signature;
    }

    public InputInformation signature(String signature) {
        this.signature = signature;
        return this;
    }

    public Integer getYears() {
        return years;
    }

    public InputInformation years(Integer years) {
        this.years = years;
        return this;
    }

    public String getIssuer() {
        return issuer;
    }

    public InputInformation issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public InputInformation subject(String subject) {
        this.subject = subject;
        return this;
    }

}
