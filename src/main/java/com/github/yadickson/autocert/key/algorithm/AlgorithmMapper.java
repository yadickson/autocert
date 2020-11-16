/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.algorithm;

import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;

import javax.inject.Named;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class AlgorithmMapper implements Function<String, Algorithm> {

    private static final String EMPTY = "";

    @Override
    public Algorithm apply(final String algorithm) {
        try {
            final String value = Optional.ofNullable(algorithm).orElse(EMPTY).trim().toUpperCase(Locale.US);
            return Algorithm.valueOf(value);
        } catch (IllegalArgumentException ex) {
            throw new AlgorithmNotSupportException(ex);
        }
    }
}
