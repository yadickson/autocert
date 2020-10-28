/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.writer.certificate;

/**
 *
 * @author Yadickson Soto
 */
public class CertificateWriterException extends RuntimeException {

    public CertificateWriterException(final Throwable ex) {
        super(ex);
    }
}
