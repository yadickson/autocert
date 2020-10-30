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

import com.github.yadickson.autocert.Parameters;
import com.github.yadickson.autocert.key.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.keypair.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.key.provider.ProviderDecorator;

@RunWith(MockitoJUnitRunner.class)
public class CertificateGeneratorTest {

    private CertificateGenerator generator;

    private ProviderDecorator provider;

    private KeyPairGenerator keyPairGenerator;

    @Mock
    private Parameters parametersPluginMock;

    @Before
    public void setUp() {
        generator = new CertificateGenerator();
        provider = new ProviderDecorator();
        keyPairGenerator = new KeyPairGenerator(new AlgorithmMapper(), new KeyPairInitializeFactory());
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void it_should_return_rsa_certificate() throws CertificateEncodingException {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(1024);

        KeyPair keyPair = keyPairGenerator.execute(parametersPluginMock, provider);

        String signature = "SHA256withRSA";
        String issuer = "domain";
        String subject = "main";
        Integer years = 1;

        Mockito.when(parametersPluginMock.getSignature()).thenReturn(signature);
        Mockito.when(parametersPluginMock.getYears()).thenReturn(years);
        Mockito.when(parametersPluginMock.getIssuer()).thenReturn(issuer);
        Mockito.when(parametersPluginMock.getSubject()).thenReturn(subject);

        Certificate result = generator.execute(parametersPluginMock, provider, keyPair);

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

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(parametersPluginMock, provider);

        String signature = "SHA256withECDSA";
        String issuer = "domain";
        String subject = "main";
        Integer years = 1;

        Mockito.when(parametersPluginMock.getSignature()).thenReturn(signature);
        Mockito.when(parametersPluginMock.getYears()).thenReturn(years);
        Mockito.when(parametersPluginMock.getIssuer()).thenReturn(issuer);
        Mockito.when(parametersPluginMock.getSubject()).thenReturn(subject);

        Certificate result = generator.execute(parametersPluginMock, provider, keyPair);

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

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(parametersPluginMock, provider);

        String signature = "SHA256withRSA";
        String issuer = "domain";
        String subject = "main";
        Integer years = 1;

        Mockito.when(parametersPluginMock.getSignature()).thenReturn(signature);
        Mockito.when(parametersPluginMock.getYears()).thenReturn(years);
        Mockito.when(parametersPluginMock.getIssuer()).thenReturn(issuer);
        Mockito.when(parametersPluginMock.getSubject()).thenReturn(subject);

        generator.execute(parametersPluginMock, provider, keyPair);
    }

}
