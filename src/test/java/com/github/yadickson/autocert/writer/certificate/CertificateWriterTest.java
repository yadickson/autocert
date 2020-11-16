package com.github.yadickson.autocert.writer.certificate;

import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"jdk.internal.reflect.*"})
public class CertificateWriterTest {

    @Mock
    private FileWriter fileWriterMock;

    @Mock
    private Base64.Encoder base64encoderMock;

    @Mock
    private Certificate certificateMock;

    @Test
    @PrepareForTest({CertificateWriter.class})
    public void it_should_write_certificate_in_base64() throws Exception {

        final String filename = "filename";
        final byte[] encode = {' '};
        final String body = "body";

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(certificateMock.getEncoded()).thenReturn(encode);
        Mockito.when(Base64.getMimeEncoder()).thenReturn(base64encoderMock);
        Mockito.when(base64encoderMock.encodeToString(Mockito.same(encode))).thenReturn(body);

        CertificateWriter instance = new CertificateWriter();
        instance.execute(filename, certificateMock);

        InOrder inOrder = Mockito.inOrder(fileWriterMock);

        inOrder.verify(fileWriterMock).write(Mockito.eq("-----BEGIN CERTIFICATE-----\n\r"));
        inOrder.verify(fileWriterMock).write(Mockito.eq("body"));
        inOrder.verify(fileWriterMock).write(Mockito.eq("\n\r-----END CERTIFICATE-----"));
    }

    @Test(expected = CertificateWriterException.class)
    @PrepareForTest({CertificateWriter.class})
    public void it_should_throw_certificate_writer_exception_when_certificate_encoding_exception() throws Exception {

        final String filename = "filename";

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(certificateMock.getEncoded()).thenThrow(CertificateEncodingException.class);

        CertificateWriter instance = new CertificateWriter();
        instance.execute(filename, certificateMock);
    }

    @Test(expected = CertificateWriterException.class)
    @PrepareForTest({CertificateWriter.class})
    public void it_should_throw_certificate_writer_exception_when_writer_io_exception() throws Exception {

        final String filename = "filename";
        final byte[] encode = {' '};
        final String body = "body";

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(certificateMock.getEncoded()).thenReturn(encode);
        Mockito.when(Base64.getMimeEncoder()).thenReturn(base64encoderMock);
        Mockito.when(base64encoderMock.encodeToString(Mockito.same(encode))).thenReturn(body);

        Mockito.doThrow(IOException.class).when(fileWriterMock).write(Mockito.anyString());

        CertificateWriter instance = new CertificateWriter();
        instance.execute(filename, certificateMock);
    }

}
