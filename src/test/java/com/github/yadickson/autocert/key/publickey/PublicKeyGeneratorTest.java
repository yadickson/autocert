package com.github.yadickson.autocert.key.publickey;

import java.io.IOException;
import java.security.KeyPair;
import java.security.spec.EncodedKeySpec;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.initializer.ec.KeyPairEcInitialize;
import com.github.yadickson.autocert.initializer.rsa.KeyPairRsaInitialize;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.model.Algorithm;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.provider.ProviderDecorator;

@RunWith(MockitoJUnitRunner.class)
public class PublicKeyGeneratorTest {

    private PublicKeyGenerator generator;

    private ProviderDecorator provider;

    private KeyPairInitialize rsaInitializer;

    private KeyPairInitialize ecInitializer;

    private KeyPairGenerator keyPairGenerator;

    @Before
    public void setUp() {
        generator = new PublicKeyGenerator();
        provider = new ProviderDecorator(new ProviderConfiguration());
        rsaInitializer = new KeyPairRsaInitialize();
        ecInitializer = new KeyPairEcInitialize();
        keyPairGenerator = new KeyPairGenerator();
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void it_should_return_a_rsa_1024_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, rsaInitializer, Algorithm.RSA, 1024);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_rsa_2048_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, rsaInitializer, Algorithm.RSA, 2048);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_rsa_4096_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, rsaInitializer, Algorithm.RSA, 4096);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_256_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.EC, 256);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_384_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.EC, 384);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ec_521_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.EC, 521);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_256_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.ECDH, 256);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_384_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.ECDH, 384);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdh_521_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.ECDH, 521);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_256_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.ECDSA, 256);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_384_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.ECDSA, 384);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

    @Test
    public void it_should_return_a_ecdsa_521_public_key() {
        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.ECDSA, 521);

        EncodedKeySpec result = generator.execute(keyPair);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getFormat());
    }

}
