package com.github.yadickson.autocert;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.algorithm.AlgorithmNotSupportException;
import com.github.yadickson.autocert.directory.DirectoryBuilder;
import com.github.yadickson.autocert.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.key.certificate.CertificateGenerator;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.privatekey.PrivateKeyGenerator;
import com.github.yadickson.autocert.key.publickey.PublicKeyGenerator;
import com.github.yadickson.autocert.model.Algorithm;
import com.github.yadickson.autocert.model.Parameters;
import com.github.yadickson.autocert.model.Provider;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.writer.certificate.CertificateWriter;
import com.github.yadickson.autocert.writer.privatekey.PrivateKeyWriter;
import com.github.yadickson.autocert.writer.publickey.PublicKeyWriter;

@RunWith(MockitoJUnitRunner.class)
public class GeneratorPluginTest {

    private GeneratorPlugin generatorPlugin;

    @Mock
    private MavenProject projectMock;

    @Mock
    private Log logMock;

    @Mock
    private File outputDirectoryMock;

    @Mock
    private PublicKey publicKeyMock;

    @Mock
    private PrivateKey privateKeyMock;

    @Mock
    private EncodedKeySpec privateKeyEncodeMock;

    @Mock
    private EncodedKeySpec publicKeyEncodeMock;

    @Mock
    private Certificate certificateMock;

    @Mock
    private KeyPairInitialize initializerMock;

    @Mock
    private DirectoryBuilder directoryBuilderMock;

    @Mock
    private CustomResource customResourceMock;

    @Mock
    private AlgorithmMapper algorithmMapperMock;

    @Mock
    private KeyPairInitializeFactory initializerFactoryMock;

    @Mock
    private KeyPairGenerator keyPairGeneratorMock;

    @Mock
    private PrivateKeyGenerator privateKeyGeneratorMock;

    @Mock
    private PublicKeyGenerator publicKeyGeneratorMock;

    @Mock
    private CertificateGenerator certificateGeneratorMock;

    @Mock
    private PrivateKeyWriter privateKeyWriterMock;

    @Mock
    private PublicKeyWriter publicKeyWriterMock;

    @Mock
    private CertificateWriter certificateWriterMock;

    private Parameters parametersMock;

    private static final String PUBLIC_KEY_FILENAME = "public-key-filename";
    private static final String PRIVATE_KEY_FILENAME = "private-key-filename";
    private static final String CERTIFICATE_FILENAME = "certificate-filename";

    private static final String ALGORITHM = "algorithm";
    private static final Integer KEY_SIZE = 1024;

    private static final String SIGNATURE = "signature";
    private static final Integer YEARS = 4;
    private static final String ISSUER = "issuer";
    private static final String SUBJECT = "subject";

    private static final String DIRECTORY_NAME = "directory-name";
    private static final String OUTPUT_DIRECTORY = "output-directory";

    @Before
    public void setUp() {
        generatorPlugin = new GeneratorPlugin(
                new ProviderConfiguration(),
                directoryBuilderMock,
                customResourceMock,
                algorithmMapperMock,
                initializerFactoryMock,
                keyPairGeneratorMock,
                privateKeyGeneratorMock,
                publicKeyGeneratorMock,
                certificateGeneratorMock,
                privateKeyWriterMock,
                publicKeyWriterMock,
                certificateWriterMock
        );

        parametersMock = new Parameters(PUBLIC_KEY_FILENAME, PRIVATE_KEY_FILENAME, CERTIFICATE_FILENAME, ALGORITHM, KEY_SIZE, SIGNATURE, YEARS, ISSUER, SUBJECT, DIRECTORY_NAME, outputDirectoryMock);

        generatorPlugin.setLog(logMock);
        generatorPlugin.setProject(projectMock);
        generatorPlugin.setParameters(parametersMock);
    }

    @Test
    public void test_logger_messages() throws MojoExecutionException {

        Mockito.when(outputDirectoryMock.getPath()).thenReturn(OUTPUT_DIRECTORY);

        generatorPlugin.execute();

        Mockito.verify(logMock).info(Mockito.eq("[Generator] PubFile: " + PUBLIC_KEY_FILENAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] KeyFile: " + PRIVATE_KEY_FILENAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] CertFile: " + CERTIFICATE_FILENAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Algorithm: " + ALGORITHM));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Signature: " + SIGNATURE));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] KeySize: " + KEY_SIZE));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Issuer: " + ISSUER));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Subject: " + SUBJECT));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Years: " + YEARS));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] DirectoryName: " + DIRECTORY_NAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] OutputDirectory: " + OUTPUT_DIRECTORY));
    }

    @Test
    public void it_should_check_all_process() throws Exception {

        Algorithm algorithm = Algorithm.RSA;
        KeyPair keyPairMock = new KeyPair(publicKeyMock, privateKeyMock);

        Mockito.when(algorithmMapperMock.apply(Mockito.eq(ALGORITHM))).thenReturn(algorithm);
        Mockito.when(initializerFactoryMock.apply(Mockito.eq(algorithm))).thenReturn(initializerMock);
        Mockito.when(keyPairGeneratorMock.execute(Mockito.any(Provider.class), Mockito.same(initializerMock), Mockito.eq(algorithm), Mockito.eq(KEY_SIZE))).thenReturn(keyPairMock);

        Mockito.when(privateKeyGeneratorMock.execute(Mockito.same(keyPairMock))).thenReturn(privateKeyEncodeMock);
        Mockito.when(publicKeyGeneratorMock.execute(Mockito.same(keyPairMock))).thenReturn(publicKeyEncodeMock);
        Mockito.when(certificateGeneratorMock.execute(Mockito.any(Provider.class), Mockito.same(keyPairMock), Mockito.same(parametersMock))).thenReturn(certificateMock);

        generatorPlugin.execute();

        InOrder inOrder = Mockito.inOrder(directoryBuilderMock, customResourceMock, algorithmMapperMock, initializerFactoryMock, keyPairGeneratorMock, privateKeyGeneratorMock, publicKeyGeneratorMock, certificateGeneratorMock, privateKeyWriterMock, publicKeyWriterMock, certificateWriterMock);

        inOrder.verify(algorithmMapperMock).apply(Mockito.eq(ALGORITHM));
        inOrder.verify(initializerFactoryMock).apply(Mockito.eq(algorithm));

        inOrder.verify(keyPairGeneratorMock).execute(Mockito.any(Provider.class), Mockito.same(initializerMock), Mockito.eq(algorithm), Mockito.eq(KEY_SIZE));
        inOrder.verify(privateKeyGeneratorMock).execute(Mockito.same(keyPairMock));
        inOrder.verify(publicKeyGeneratorMock).execute(Mockito.same(keyPairMock));
        inOrder.verify(certificateGeneratorMock).execute(Mockito.any(Provider.class), Mockito.same(keyPairMock), Mockito.same(parametersMock));

        inOrder.verify(directoryBuilderMock).execute(Mockito.anyString());
        inOrder.verify(customResourceMock).execute(Mockito.same(projectMock), Mockito.anyString());

        inOrder.verify(privateKeyWriterMock).execute(Mockito.anyString(), Mockito.same(privateKeyEncodeMock));
        inOrder.verify(publicKeyWriterMock).execute(Mockito.anyString(), Mockito.same(publicKeyEncodeMock));
        inOrder.verify(certificateWriterMock).execute(Mockito.anyString(), Mockito.same(certificateMock));
    }

    @Test(expected = MojoExecutionException.class)
    public void it_should_throw_error_when_algorithm_not_support_exception() throws Exception {
        Mockito.when(algorithmMapperMock.apply(Mockito.eq(ALGORITHM))).thenThrow(AlgorithmNotSupportException.class);
        generatorPlugin.execute();
    }
}
