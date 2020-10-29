package com.github.yadickson.autocert.key.publickey;

import java.io.IOException;
import java.security.KeyPair;
import java.security.spec.EncodedKeySpec;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.Parameters;
import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.provider.ProviderDecorator;

@RunWith(MockitoJUnitRunner.class)
public class PublicKeyGeneratorTest {

    private PublicKeyGenerator generator;

    private ProviderDecorator provider;

    private KeyPairGenerator keyPairGenerator;

    @Mock
    private Parameters parametersPluginMock;

    @Before
    public void setUp() {
        generator = new PublicKeyGenerator();
        provider = new ProviderDecorator(new ProviderConfiguration());
        keyPairGenerator = new KeyPairGenerator(new AlgorithmMapper(), new KeyPairInitializeFactory());
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void it_should_return_a_rsa_1024_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(1024);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_rsa_2048_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(2048);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_rsa_4096_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(4096);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_256_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_384_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(384);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_521_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(521);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_256_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_384_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(384);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_521_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(521);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_256_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_384_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(384);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_521_public_key() {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(521);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

}
