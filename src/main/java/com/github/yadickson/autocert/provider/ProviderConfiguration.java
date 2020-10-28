/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert.provider;

import com.github.yadickson.autocert.model.Provider;
import java.util.function.Supplier;
import javax.inject.Named;
import javax.inject.Singleton;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Yadickson Soto
 */
@Named
@Singleton
public class ProviderConfiguration implements Supplier<Provider>{

    @Override
    public Provider get() {
        return new Provider(new BouncyCastleProvider(), BouncyCastleProvider.PROVIDER_NAME);
    }
}
