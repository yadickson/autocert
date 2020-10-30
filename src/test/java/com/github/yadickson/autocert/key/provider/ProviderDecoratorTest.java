package com.github.yadickson.autocert.key.provider;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"jdk.internal.reflect.*"})
public class ProviderDecoratorTest {

    @Captor
    private ArgumentCaptor<java.security.Provider> argumentProviderCapture;

    @Test
    @PrepareForTest({ProviderDecorator.class})
    public void it_should_set_provider_when_is_made_a_new_instance() throws Exception {

        PowerMockito.mockStatic(Security.class);
        PowerMockito.when(Security.addProvider(argumentProviderCapture.capture())).thenReturn(0);

        ProviderDecorator decorator = new ProviderDecorator();
        Assert.assertTrue(decorator instanceof Provider);
        Assert.assertTrue(decorator.getProvider() instanceof BouncyCastleProvider);
        Assert.assertEquals(BouncyCastleProvider.PROVIDER_NAME, decorator.getName());

        java.security.Provider provider = argumentProviderCapture.getValue();

        Assert.assertNotNull(provider);
        Assert.assertTrue(provider instanceof BouncyCastleProvider);
    }

    @Test
    @PrepareForTest({ProviderDecorator.class})
    public void it_should_close_provider_when_close_was_called() throws Exception {

        PowerMockito.mockStatic(Security.class);
        PowerMockito.when(Security.addProvider(Mockito.isNotNull(java.security.Provider.class))).thenReturn(0);

        ProviderDecorator decorator = new ProviderDecorator();
        decorator.close();
    }

}
