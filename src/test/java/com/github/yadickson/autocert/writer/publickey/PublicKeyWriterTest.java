package com.github.yadickson.autocert.writer.publickey;

import java.io.FileWriter;
import java.security.spec.EncodedKeySpec;
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
public class PublicKeyWriterTest {

    @Mock
    private FileWriter fileWriterMock;

    @Mock
    private Base64.Encoder base64encoderMock;

    @Mock
    private EncodedKeySpec publicKeyMock;

    @Test
    @PrepareForTest({PublicKeyWriter.class})
    public void it_should_write_public_key_in_base64() throws Exception {

        final String filename = "filename";
        final byte[] encode = {' '};
        final String body = "body";

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(publicKeyMock.getEncoded()).thenReturn(encode);
        Mockito.when(Base64.getMimeEncoder()).thenReturn(base64encoderMock);
        Mockito.when(base64encoderMock.encodeToString(Mockito.same(encode))).thenReturn(body);

        PublicKeyWriter instance = new PublicKeyWriter();
        instance.execute(filename, publicKeyMock);

        InOrder inOrder = Mockito.inOrder(fileWriterMock);

        inOrder.verify(fileWriterMock).write(Mockito.eq("-----BEGIN PUBLIC KEY-----\n\r"));
        inOrder.verify(fileWriterMock).write(Mockito.eq("body"));
        inOrder.verify(fileWriterMock).write(Mockito.eq("\n\r-----END PUBLIC KEY-----"));

    }

    @Test(expected = PublicKeyWriterException.class)
    @PrepareForTest({PublicKeyWriter.class})
    public void it_should_throw_public_key_writer_exception_when_error() throws Exception {

        final String filename = "filename";
        final byte[] encode = {' '};

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(publicKeyMock.getEncoded()).thenReturn(encode);
        Mockito.when(Base64.getMimeEncoder()).thenReturn(base64encoderMock);
        Mockito.when(base64encoderMock.encodeToString(Mockito.same(encode))).thenThrow(RuntimeException.class);

        PublicKeyWriter instance = new PublicKeyWriter();
        instance.execute(filename, publicKeyMock);
    }

}
