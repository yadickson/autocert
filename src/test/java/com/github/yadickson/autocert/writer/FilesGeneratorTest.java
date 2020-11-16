package com.github.yadickson.autocert.writer;

import java.io.File;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.key.KeysResponse;
import com.github.yadickson.autocert.parameters.OutputInformation;
import com.github.yadickson.autocert.parameters.Parameters;
import com.github.yadickson.autocert.writer.certificate.CertificateWriter;
import com.github.yadickson.autocert.writer.certificate.CertificateWriterException;
import com.github.yadickson.autocert.writer.privatekey.PrivateKeyWriter;
import com.github.yadickson.autocert.writer.privatekey.PrivateKeyWriterException;
import com.github.yadickson.autocert.writer.publickey.PublicKeyWriter;
import com.github.yadickson.autocert.writer.publickey.PublicKeyWriterException;

@RunWith(MockitoJUnitRunner.class)
public class FilesGeneratorTest {

    private FilesGenerator generator;

    @Mock
    private PrivateKeyWriter privateKeyWriterMock;

    @Mock
    private PublicKeyWriter publicKeyWriterMock;

    @Mock
    private CertificateWriter certificateWriterMock;

    @Mock
    private OutputInformation outputInformationMock;

    @Mock
    private Parameters parametersMock;

    @Mock
    private EncodedKeySpec privateKeyMock;

    @Mock
    private EncodedKeySpec publicKeyMock;

    @Mock
    private Certificate certificateMock;

    @Mock
    private KeysResponse keysResponseMock;

    private static final String DIRECTORY_NAME = "directory-name";
    private static final String OUTPUT_DIRECTORY = "output-directory";

    private static final String PRIVATE_NAME = "private-name";
    private static final String PUBLIC_NAME = "public-name";
    private static final String CERTIFICATE_NAME = "certificate-name";

    private static final String PRIVATE_PATH = OUTPUT_DIRECTORY + File.separator + DIRECTORY_NAME + File.separator + PRIVATE_NAME;
    private static final String PUBLIC_PATH = OUTPUT_DIRECTORY + File.separator + DIRECTORY_NAME + File.separator + PUBLIC_NAME;
    private static final String CERTIFICATE_PATH = OUTPUT_DIRECTORY + File.separator + DIRECTORY_NAME + File.separator + CERTIFICATE_NAME;

    @Before
    public void setUp() {
        generator = new FilesGenerator(
                privateKeyWriterMock,
                publicKeyWriterMock,
                certificateWriterMock
        );

        Mockito.when(parametersMock.getOutput()).thenReturn(outputInformationMock);
    }

    @Test
    public void it_should_make_all_files() {

        Mockito.when(keysResponseMock.getPrivateKey()).thenReturn(privateKeyMock);
        Mockito.when(keysResponseMock.getPublicKey()).thenReturn(publicKeyMock);
        Mockito.when(keysResponseMock.getCertificate()).thenReturn(certificateMock);

        Mockito.when(outputInformationMock.getKeyFilename()).thenReturn(PRIVATE_NAME);
        Mockito.when(outputInformationMock.getPubFilename()).thenReturn(PUBLIC_NAME);
        Mockito.when(outputInformationMock.getCertFilename()).thenReturn(CERTIFICATE_NAME);
        Mockito.when(outputInformationMock.getDirectoryName()).thenReturn(DIRECTORY_NAME);
        Mockito.when(outputInformationMock.getOutputDirectory()).thenReturn(OUTPUT_DIRECTORY);

        generator.execute(parametersMock, keysResponseMock);

        InOrder inOrder = Mockito.inOrder(privateKeyWriterMock, publicKeyWriterMock, certificateWriterMock);

        inOrder.verify(privateKeyWriterMock).execute(Mockito.eq(PRIVATE_PATH), Mockito.same(privateKeyMock));
        inOrder.verify(publicKeyWriterMock).execute(Mockito.eq(PUBLIC_PATH), Mockito.same(publicKeyMock));
        inOrder.verify(certificateWriterMock).execute(Mockito.eq(CERTIFICATE_PATH), Mockito.same(certificateMock));
    }

    @Test(expected = FilesGeneratorException.class)
    public void it_should_throw_an_error_when_private_key_writer_exception() {
        Mockito.doThrow(PrivateKeyWriterException.class).when(privateKeyWriterMock).execute(Mockito.anyString(), Mockito.any(EncodedKeySpec.class));
        generator.execute(parametersMock, keysResponseMock);
    }

    @Test(expected = FilesGeneratorException.class)
    public void it_should_throw_an_error_when_public_key_writer_exception() {
        Mockito.doThrow(PublicKeyWriterException.class).when(publicKeyWriterMock).execute(Mockito.anyString(), Mockito.any(EncodedKeySpec.class));
        generator.execute(parametersMock, keysResponseMock);
    }

    @Test(expected = FilesGeneratorException.class)
    public void it_should_throw_an_error_when_certificate_writer_exception() {
        Mockito.doThrow(CertificateWriterException.class).when(certificateWriterMock).execute(Mockito.anyString(), Mockito.any(Certificate.class));
        generator.execute(parametersMock, keysResponseMock);
    }

}
