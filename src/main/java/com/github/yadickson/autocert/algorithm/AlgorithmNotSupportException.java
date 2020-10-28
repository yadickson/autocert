/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.algorithm;

/**
 *
 * @author Yadickson Soto
 */
public class AlgorithmNotSupportException extends RuntimeException {

    public AlgorithmNotSupportException(final Throwable ex) {
        super(ex);
    }
}
