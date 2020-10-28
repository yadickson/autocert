package com.github.yadickson.autocert.initializer;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.initializer.ec.KeyPairEcInitialize;
import com.github.yadickson.autocert.initializer.rsa.KeyPairRsaInitialize;
import com.github.yadickson.autocert.model.Algorithm;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairInitializeFactoryTest {

    private KeyPairInitializeFactory factory;

    @Before
    public void setUp() {
        factory = new KeyPairInitializeFactory();
    }

    @Test
    public void it_should_return_rsa_initializer_when_input_is_algorithm_rsa() {
        KeyPairInitialize result = factory.apply(Algorithm.RSA);

        Assert.assertNotNull(result);
        Assert.assertTrue(result instanceof KeyPairRsaInitialize);
    }

    @Test
    public void it_should_return_ec_initializer_when_input_is_algorithm_ec() {
        KeyPairInitialize result = factory.apply(Algorithm.EC);

        Assert.assertNotNull(result);
        Assert.assertTrue(result instanceof KeyPairEcInitialize);
    }

    @Test
    public void it_should_return_ec_initializer_when_input_is_algorithm_ecdh() {
        KeyPairInitialize result = factory.apply(Algorithm.ECDH);

        Assert.assertNotNull(result);
        Assert.assertTrue(result instanceof KeyPairEcInitialize);
    }

    @Test
    public void it_should_return_ec_initializer_when_input_is_algorithm_ecdsa() {
        KeyPairInitialize result = factory.apply(Algorithm.ECDSA);

        Assert.assertNotNull(result);
        Assert.assertTrue(result instanceof KeyPairEcInitialize);
    }

    @Test(expected = KeyPairInitializeNotSupportException.class)
    public void it_should_throw_error_when_algorithm_is_not_supported() {
        KeyPairInitialize result = factory.apply(Algorithm.OTHER);

        Assert.assertNotNull(result);
        Assert.assertTrue(result instanceof KeyPairEcInitialize);
    }

}
