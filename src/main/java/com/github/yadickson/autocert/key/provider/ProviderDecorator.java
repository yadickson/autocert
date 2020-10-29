/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.key.provider;

import java.io.Closeable;
import java.io.IOException;
import java.security.Security;
import javax.inject.Named;
import javax.inject.Singleton;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class ProviderDecorator extends Provider implements Closeable {
  
    public ProviderDecorator() {
        super(new BouncyCastleProvider(), BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(this.getProvider());
    }

    @Override
    public void close() throws IOException {
        Security.removeProvider(this.getName());
    }

}
