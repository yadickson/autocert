package com.github.yadickson.autocert.initializer.ec;

import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairEcInitializeTest {

    private KeyPairEcInitialize initializer;

    @Mock
    private KeyPairGenerator keyPairGeneratorMock;

    @Captor
    private ArgumentCaptor<AlgorithmParameterSpec> argumentCaptor;

    @Before
    public void setUp() {
        initializer = new KeyPairEcInitialize();
    }

    @Test
    public void it_should_call_initialize_from_key_pair_generator() throws Exception {
        Integer keySize = 256;

        Mockito.doNothing().when(keyPairGeneratorMock).initialize(argumentCaptor.capture());

        initializer.execute(keyPairGeneratorMock, keySize);

        Mockito.verify(keyPairGeneratorMock).initialize(argumentCaptor.capture());

        AlgorithmParameterSpec argument = argumentCaptor.getValue();

        Assert.assertNotNull(argument);
        Assert.assertTrue(argument instanceof ECGenParameterSpec);

        ECGenParameterSpec parameter = (ECGenParameterSpec) argument;

        Assert.assertNotNull(parameter);
        Assert.assertEquals("secp256r1", parameter.getName());
    }

}
