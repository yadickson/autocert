/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.provider;

/**
 *
 * @author Yadickson Soto
 */
public class Provider {

    private final java.security.Provider provider;
    private final String name;

    public Provider(final Provider securityProvider) {
        this(securityProvider.getProvider(), securityProvider.getName());
    }

    public Provider(final java.security.Provider provider, final String name) {
        this.provider = provider;
        this.name = name;
    }

    public java.security.Provider getProvider() {
        return provider;
    }

    public String getName() {
        return name;
    }

}
