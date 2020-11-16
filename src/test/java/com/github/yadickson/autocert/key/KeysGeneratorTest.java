package com.github.yadickson.autocert.key;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.github.yadickson.autocert.parameters.Parameters;
import com.github.yadickson.autocert.key.certificate.CertificateGenerator;
import com.github.yadickson.autocert.key.certificate.CertificateGeneratorException;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.keypair.KeyPairGeneratorException;
import com.github.yadickson.autocert.key.privatekey.PrivateKeyGenerator;
import com.github.yadickson.autocert.key.provider.Provider;
import com.github.yadickson.autocert.key.provider.ProviderDecorator;
import com.github.yadickson.autocert.key.publickey.PublicKeyGenerator;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"jdk.internal.reflect.*"})
public class KeysGeneratorTest {

    private KeysGenerator generator;

    @Mock
    private KeyPairGenerator keyPairGeneratorMock;

    @Mock
    private PrivateKeyGenerator privateKeyGeneratorMock;

    @Mock
    private PublicKeyGenerator publicKeyGeneratorMock;

    @Mock
    private CertificateGenerator certificateGeneratorMock;

    @Mock
    private Parameters parametersMock;

    @Mock
    private KeyPair keyPairMock;

    @Mock
    private EncodedKeySpec privateKeyMock;

    @Mock
    private EncodedKeySpec publicKeyMock;

    @Mock
    private Certificate certificateMock;

    @Mock
    private ProviderDecorator providerDecoratorMock;

    @Before
    public void setUp() {
        generator = new KeysGenerator(
                keyPairGeneratorMock,
                privateKeyGeneratorMock,
                publicKeyGeneratorMock,
                certificateGeneratorMock
        );
    }

    @Test
    public void it_should_return_keys_result() {

        Mockito.when(keyPairGeneratorMock.execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class))).thenReturn(keyPairMock);
        Mockito.when(privateKeyGeneratorMock.execute(Mockito.same(keyPairMock))).thenReturn(privateKeyMock);
        Mockito.when(publicKeyGeneratorMock.execute(Mockito.same(keyPairMock))).thenReturn(publicKeyMock);
        Mockito.when(certificateGeneratorMock.execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class), Mockito.same(keyPairMock))).thenReturn(certificateMock);

        KeysResponse response = generator.execute(parametersMock);

        Assert.assertNotNull(response);
        Assert.assertSame(privateKeyMock, response.getPrivateKey());
        Assert.assertSame(publicKeyMock, response.getPublicKey());
        Assert.assertSame(certificateMock, response.getCertificate());

        InOrder inOrder = Mockito.inOrder(keyPairGeneratorMock, privateKeyGeneratorMock, publicKeyGeneratorMock, certificateGeneratorMock);

        inOrder.verify(keyPairGeneratorMock).execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class));
        inOrder.verify(privateKeyGeneratorMock).execute(Mockito.same(keyPairMock));
        inOrder.verify(publicKeyGeneratorMock).execute(Mockito.same(keyPairMock));
        inOrder.verify(certificateGeneratorMock).execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class), Mockito.same(keyPairMock));
    }

    @Test(expected = KeysGeneratorException.class)
    public void it_should_throw_error_when_key_pair_generator_exception() {
        Mockito.when(keyPairGeneratorMock.execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class))).thenThrow(KeyPairGeneratorException.class);
        generator.execute(parametersMock);
    }

    @Test(expected = KeysGeneratorException.class)
    public void it_should_throw_error_when_certificate_generator_exception() {
        Mockito.when(certificateGeneratorMock.execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class), Mockito.any(KeyPair.class))).thenThrow(CertificateGeneratorException.class);
        generator.execute(parametersMock);
    }

    @Test
    @PrepareForTest({KeysGenerator.class})
    public void it_should_check_provider_decorator_was_closed() throws Exception {

        Mockito.when(keyPairGeneratorMock.execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class))).thenReturn(keyPairMock);
        Mockito.when(privateKeyGeneratorMock.execute(Mockito.same(keyPairMock))).thenReturn(privateKeyMock);
        Mockito.when(publicKeyGeneratorMock.execute(Mockito.same(keyPairMock))).thenReturn(publicKeyMock);
        Mockito.when(certificateGeneratorMock.execute(Mockito.same(parametersMock), Mockito.isNotNull(Provider.class), Mockito.same(keyPairMock))).thenReturn(certificateMock);

        KeysGenerator keysGenerator = new KeysGenerator(
                keyPairGeneratorMock,
                privateKeyGeneratorMock,
                publicKeyGeneratorMock,
                certificateGeneratorMock
        );

        PowerMockito.whenNew(ProviderDecorator.class).withAnyArguments().thenReturn(providerDecoratorMock);

        keysGenerator.execute(parametersMock);

        Mockito.verify(providerDecoratorMock).close();
    }

}
