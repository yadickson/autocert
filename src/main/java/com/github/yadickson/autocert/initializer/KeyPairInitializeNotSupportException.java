/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.initializer;

/**
 *
 * @author Yadickson Soto
 */
public class KeyPairInitializeNotSupportException extends RuntimeException {

    public KeyPairInitializeNotSupportException(final String message) {
        super(message);
    }
}
