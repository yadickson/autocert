package com.github.yadickson.autocert.writer.privatekey;

import java.io.FileWriter;
import java.io.IOException;
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
public class PrivateKeyWriterTest {

    @Mock
    private FileWriter fileWriterMock;

    @Mock
    private Base64.Encoder base64encoderMock;

    @Mock
    private EncodedKeySpec privateKeyMock;

    @Test
    @PrepareForTest({PrivateKeyWriter.class})
    public void it_should_write_private_key_in_base64() throws Exception {

        final String filename = "filename";
        final byte[] encode = {' '};
        final String body = "body";

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(privateKeyMock.getEncoded()).thenReturn(encode);
        Mockito.when(Base64.getMimeEncoder()).thenReturn(base64encoderMock);
        Mockito.when(base64encoderMock.encodeToString(Mockito.same(encode))).thenReturn(body);

        PrivateKeyWriter instance = new PrivateKeyWriter();
        instance.execute(filename, privateKeyMock);

        InOrder inOrder = Mockito.inOrder(fileWriterMock);

        inOrder.verify(fileWriterMock).write(Mockito.eq("-----BEGIN PRIVATE KEY-----\n\r"));
        inOrder.verify(fileWriterMock).write(Mockito.eq("body"));
        inOrder.verify(fileWriterMock).write(Mockito.eq("\n\r-----END PRIVATE KEY-----"));

    }

    @Test(expected = PrivateKeyWriterException.class)
    @PrepareForTest({PrivateKeyWriter.class})
    public void it_should_throw_private_key_writer_exception_when_error() throws Exception {

        final String filename = "filename";
        final byte[] encode = {' '};
        final String body = "body";

        PowerMockito.whenNew(FileWriter.class).withArguments(filename).thenReturn(fileWriterMock);
        PowerMockito.mockStatic(Base64.class);

        Mockito.when(privateKeyMock.getEncoded()).thenReturn(encode);
        Mockito.when(Base64.getMimeEncoder()).thenReturn(base64encoderMock);
        Mockito.when(base64encoderMock.encodeToString(Mockito.same(encode))).thenReturn(body);

        Mockito.doThrow(IOException.class).when(fileWriterMock).write(Mockito.anyString());

        PrivateKeyWriter instance = new PrivateKeyWriter();
        instance.execute(filename, privateKeyMock);
    }

}
