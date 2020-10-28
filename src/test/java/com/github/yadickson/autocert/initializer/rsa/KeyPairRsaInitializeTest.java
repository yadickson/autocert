package com.github.yadickson.autocert.initializer.rsa;

import java.security.KeyPairGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairRsaInitializeTest {

    private KeyPairRsaInitialize initializer;

    @Mock
    private KeyPairGenerator keyPairGeneratorMock;

    @Before
    public void setUp() {
        initializer = new KeyPairRsaInitialize();
    }

    @Test
    public void it_should_call_initialize_from_key_pair_generator() throws Exception {
        Integer keySize = 256;

        Mockito.doNothing().when(keyPairGeneratorMock).initialize(Mockito.eq(keySize));

        initializer.execute(keyPairGeneratorMock, keySize);

        Mockito.verify(keyPairGeneratorMock).initialize(Mockito.eq(keySize));
    }

}
