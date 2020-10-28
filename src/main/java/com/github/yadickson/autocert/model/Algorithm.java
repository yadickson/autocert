/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.model;

/**
 *
 * @author Yadickson Soto
 */
public enum Algorithm {

    RSA("RSA"),
    EC("EC"),
    ECDSA("ECDSA"),
    ECDH("ECDH"),
    OTHER("OTHER");

    private final String message;

    private Algorithm(final String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

}
