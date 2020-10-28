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
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.initializer.ec.KeyPairEcInitialize;
import com.github.yadickson.autocert.initializer.rsa.KeyPairRsaInitialize;
import com.github.yadickson.autocert.model.Algorithm;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.provider.ProviderDecorator;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairGeneratorTest {

    private KeyPairGenerator generator;

    private ProviderDecorator provider;

    private KeyPairInitialize rsaInitializer;

    private KeyPairInitialize ecInitializer;

    @Before
    public void setUp() {
        generator = new KeyPairGenerator();
        provider = new ProviderDecorator(new ProviderConfiguration());
        rsaInitializer = new KeyPairRsaInitialize();
        ecInitializer = new KeyPairEcInitialize();
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void it_should_return_rsa_1024_key_pair() {

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.RSA, 1024);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.RSA, 2048);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.RSA, 4096);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.EC, 256);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.EC, 384);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.EC, 521);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.ECDH, 256);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.ECDH, 384);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.ECDH, 521);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.ECDSA, 256);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.ECDSA, 384);

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

        KeyPair result = generator.execute(provider, rsaInitializer, Algorithm.ECDSA, 521);

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
        generator.execute(provider, rsaInitializer, Algorithm.ECDSA, 1024);
    }

    @Test(expected = KeyPairGeneratorException.class)
    public void it_should_throw_error_when_algorithm_is_not_support() {
        generator.execute(provider, rsaInitializer, Algorithm.OTHER, 521);
    }

}
