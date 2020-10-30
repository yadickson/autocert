/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.writer;

import com.github.yadickson.autocert.key.*;

/**
 *
 * @author Yadickson Soto
 */
public final class FilesGeneratorException extends RuntimeException {

    public FilesGeneratorException(final Throwable ex) {
        super(ex);
    }
}
