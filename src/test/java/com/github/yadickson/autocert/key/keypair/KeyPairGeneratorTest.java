package com.github.yadickson.autocert.key.keypair;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.key.provider.ProviderDecorator;
import com.github.yadickson.autocert.parameters.InputInformation;
import com.github.yadickson.autocert.parameters.Parameters;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairGeneratorTest {

    private KeyPairGenerator generator;

    private ProviderDecorator provider;

    @Mock
    private InputInformation inputInformationMock;

    @Mock
    private Parameters parametersMock;

    @Before
    public void setUp() {
        generator = new KeyPairGenerator(new AlgorithmMapper(), new KeyPairInitializeFactory());
        provider = new ProviderDecorator();

        Mockito.when(parametersMock.getInput()).thenReturn(inputInformationMock);
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void it_should_return_rsa_1024_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(1024);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("RSA", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("RSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_rsa_2048_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(2048);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("RSA", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("RSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_rsa_4096_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(4096);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("RSA", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("RSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ec_256_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(256);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("EC", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("EC", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ec_384_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(384);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("EC", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("EC", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ec_521_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(521);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("EC", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("EC", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ecdh_256_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(256);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("ECDH", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("ECDH", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ecdh_384_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(384);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("ECDH", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("ECDH", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ecdh_521_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(521);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("ECDH", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("ECDH", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ecdsa_256_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(256);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("ECDSA", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("ECDSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ecdsa_384_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(384);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("ECDSA", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("ECDSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ecdsa_521_key_pair() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(521);

        KeyPair result = generator.execute(parametersMock, provider);

        Assert.assertNotNull(result);

        PrivateKey privateKey = result.getPrivate();

        Assert.assertNotNull(privateKey);
        Assert.assertEquals("ECDSA", privateKey.getAlgorithm());
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());

        PublicKey publicKey = result.getPublic();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("ECDSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test(expected = KeyPairGeneratorException.class)
    public void it_should_throw_error_when_key_size_is_not_support() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(1024);

        generator.execute(parametersMock, provider);
    }

    @Test(expected = KeyPairGeneratorException.class)
    public void it_should_throw_error_when_algorithm_is_not_support() {

        Mockito.when(inputInformationMock.getAlgorithm()).thenReturn("HMAC");
        Mockito.when(inputInformationMock.getKeySize()).thenReturn(1024);

        generator.execute(parametersMock, provider);
    }

}
