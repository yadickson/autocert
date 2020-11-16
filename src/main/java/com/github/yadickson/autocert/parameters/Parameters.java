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
public class Parameters {

    private final InputInformation input;
    private final OutputInformation output;

    public Parameters(InputInformation input, OutputInformation output) {
        this.input = input;
        this.output = output;
    }

    public InputInformation getInput() {
        return input;
    }

    public OutputInformation getOutput() {
        return output;
    }

}
