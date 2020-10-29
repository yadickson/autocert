/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.algorithm;

import java.util.Locale;
import java.util.function.Function;

import javax.inject.Named;
import javax.inject.Singleton;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class AlgorithmMapper implements Function<String, Algorithm> {

    @Override
    public Algorithm apply(final String algorithm) {
        try {
            final String value = algorithm.trim().toUpperCase(Locale.US);
            return Algorithm.valueOf(value);
        } catch (Exception ex) {
            throw new AlgorithmNotSupportException(ex);
        }
    }
}
