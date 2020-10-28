package com.github.yadickson.autocert.key.certificate;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.model.Parameters;
import com.github.yadickson.autocert.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.initializer.ec.KeyPairEcInitialize;
import com.github.yadickson.autocert.initializer.rsa.KeyPairRsaInitialize;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.model.Algorithm;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.provider.ProviderDecorator;

@RunWith(MockitoJUnitRunner.class)
public class CertificateGeneratorTest {

    private CertificateGenerator generator;

    private ProviderDecorator provider;

    private KeyPairInitialize rsaInitializer;

    private KeyPairInitialize ecInitializer;

    private KeyPairGenerator keyPairGenerator;

    @Mock
    private Parameters parametersPluginMock;

    @Before
    public void setUp() {
        generator = new CertificateGenerator();
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
    public void it_should_return_rsa_certificate() throws CertificateEncodingException {

        KeyPair keyPair = keyPairGenerator.execute(provider, rsaInitializer, Algorithm.RSA, 1024);

        String signature = "SHA256withRSA";
        String issuer = "domain";
        String subject = "main";
        Integer years = 1;

        Mockito.when(parametersPluginMock.getSignature()).thenReturn(signature);
        Mockito.when(parametersPluginMock.getYears()).thenReturn(years);
        Mockito.when(parametersPluginMock.getIssuer()).thenReturn(issuer);
        Mockito.when(parametersPluginMock.getSubject()).thenReturn(subject);

        Certificate result = generator.execute(provider, keyPair, parametersPluginMock);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getType());

        PublicKey publicKey = result.getPublicKey();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("RSA", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test
    public void it_should_return_ec_certificate() throws CertificateEncodingException {

        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.EC, 256);

        String signature = "SHA256withECDSA";
        String issuer = "domain";
        String subject = "main";
        Integer years = 1;

        Mockito.when(parametersPluginMock.getSignature()).thenReturn(signature);
        Mockito.when(parametersPluginMock.getYears()).thenReturn(years);
        Mockito.when(parametersPluginMock.getIssuer()).thenReturn(issuer);
        Mockito.when(parametersPluginMock.getSubject()).thenReturn(subject);

        Certificate result = generator.execute(provider, keyPair, parametersPluginMock);

        Assert.assertNotNull(result);
        Assert.assertNotNull(result.getEncoded());
        Assert.assertEquals("X.509", result.getType());

        PublicKey publicKey = result.getPublicKey();

        Assert.assertNotNull(publicKey);
        Assert.assertEquals("EC", publicKey.getAlgorithm());
        Assert.assertNotNull(publicKey.getEncoded());
        Assert.assertEquals("X.509", publicKey.getFormat());
    }

    @Test(expected = CertificateGeneratorException.class)
    public void it_should_throw_error_when_signature_is_wrong() {

        KeyPair keyPair = keyPairGenerator.execute(provider, ecInitializer, Algorithm.EC, 256);

        String signature = "SHA256withRSA";
        String issuer = "domain";
        String subject = "main";
        Integer years = 1;

        Mockito.when(parametersPluginMock.getSignature()).thenReturn(signature);
        Mockito.when(parametersPluginMock.getYears()).thenReturn(years);
        Mockito.when(parametersPluginMock.getIssuer()).thenReturn(issuer);
        Mockito.when(parametersPluginMock.getSubject()).thenReturn(subject);

        generator.execute(provider, keyPair, parametersPluginMock);
    }

}
