/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.certificate;

/**
 *
 * @author Yadickson Soto
 */
public final class CertificateGeneratorException extends RuntimeException {

    public CertificateGeneratorException(final Throwable ex) {
        super(ex);
    }
}
