package com.github.yadickson.autocert.key.privatekey;

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

import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.key.provider.ProviderDecorator;
import com.github.yadickson.autocert.parameters.InputInformation;
import com.github.yadickson.autocert.parameters.Parameters;

@RunWith(MockitoJUnitRunner.class)
public class PrivateKeyGeneratorTest {

    private PrivateKeyGenerator generator;

    private ProviderDecorator provider;

    private KeyPairGenerator keyPairGenerator;

    @Mock
    private InputInformation inputInformationMock;

    @Mock
    private Parameters parametersMock;

    @Before
    public void setUp() {
        generator = new PrivateKeyGenerator();
        provider = new ProviderDecorator();
        keyPairGenerator = new KeyPairGenerator(new AlgorithmMapper(), new KeyPairInitializeFactory());

        Mockito.when(parametersMock.getInput()).thenReturn(inputInformationMock);
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void it_should_return_a_rsa_1024_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(1024);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_rsa_2048_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(2048);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_rsa_4096_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(4096);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_256_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_384_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(384);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_521_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(521);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_256_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_384_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(384);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_521_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(521);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_256_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_384_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(384);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_521_private_key() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(521);

        KeyPair keyPair = keyPairGenerator.execute(parametersMock, provider);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("PKCS#8", result.getFormat());
    }

}
