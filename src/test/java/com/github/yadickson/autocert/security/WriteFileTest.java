/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.autocert.security;

import java.io.FileWriter;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
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

/**
 *
 * @author Yadickson Soto
 */
@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"jdk.internal.reflect.*"})
@PrepareForTest({WriteFileImpl.class})
public class WriteFileTest {

    @Mock
    private FileWriter fileWriter;

    @Mock
    private Log log;

    @Mock
    private PKCS8EncodedKeySpec pkcs8;

    @Mock
    private X509EncodedKeySpec x509;

    @Mock
    private Base64.Encoder encoder;

    @Before
    public void setUp() {
    }

    @Test
    public void testWritePrivateKey() throws Exception {

        byte[] keys = new byte[0];
        byte[] pcksEncode = new byte[0];

        PowerMockito.whenNew(FileWriter.class).withArguments("fileName").thenReturn(fileWriter);
        PowerMockito.whenNew(PKCS8EncodedKeySpec.class).withArguments(keys).thenReturn(pkcs8);
        PowerMockito.when(pkcs8.getEncoded()).thenReturn(pcksEncode);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.getMimeEncoder()).thenReturn(encoder);
        PowerMockito.when(encoder.encodeToString(Mockito.same(pcksEncode))).thenReturn("body");

        WriteFile writeFile = new WriteFileImpl();
        writeFile.writePrivateKey("fileName", keys, log);

        InOrder inOrder = Mockito.inOrder(fileWriter);

        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("-----BEGIN PRIVATE KEY-----\n\r"));
        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("body"));
        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("\n\r-----END PRIVATE KEY-----"));
    }

    @Test(expected = MojoExecutionException.class)
    public void testWritePrivateKeyError() throws Exception {

        byte[] keys = new byte[0];
        byte[] pcksEncode = new byte[0];

        PowerMockito.whenNew(FileWriter.class).withArguments("fileName").thenReturn(fileWriter);
        PowerMockito.whenNew(PKCS8EncodedKeySpec.class).withArguments(keys).thenReturn(pkcs8);
        PowerMockito.when(pkcs8.getEncoded()).thenReturn(pcksEncode);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.getMimeEncoder()).thenReturn(encoder);
        PowerMockito.when(encoder.encodeToString(Mockito.same(pcksEncode))).thenThrow(new RuntimeException("error"));

        WriteFile writeFile = new WriteFileImpl();
        writeFile.writePrivateKey("fileName", keys, log);
    }

    @Test
    public void testWritePublicKey() throws Exception {

        byte[] keys = new byte[0];
        byte[] x509Encode = new byte[0];

        PowerMockito.whenNew(FileWriter.class).withArguments("fileName").thenReturn(fileWriter);
        PowerMockito.whenNew(X509EncodedKeySpec.class).withArguments(keys).thenReturn(x509);
        PowerMockito.when(x509.getEncoded()).thenReturn(x509Encode);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.getMimeEncoder()).thenReturn(encoder);
        PowerMockito.when(encoder.encodeToString(Mockito.same(x509Encode))).thenReturn("body");

        WriteFile writeFile = new WriteFileImpl();
        writeFile.writePublicKey("fileName", keys, log);

        InOrder inOrder = Mockito.inOrder(fileWriter);

        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("-----BEGIN PUBLIC KEY-----\n\r"));
        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("body"));
        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("\n\r-----END PUBLIC KEY-----"));
    }

    @Test(expected = MojoExecutionException.class)
    public void testWritePublicKeyError() throws Exception {

        byte[] keys = new byte[0];
        byte[] x509Encode = new byte[0];

        PowerMockito.whenNew(FileWriter.class).withArguments("fileName").thenReturn(fileWriter);
        PowerMockito.whenNew(X509EncodedKeySpec.class).withArguments(keys).thenReturn(x509);
        PowerMockito.when(x509.getEncoded()).thenReturn(x509Encode);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.getMimeEncoder()).thenReturn(encoder);
        PowerMockito.when(encoder.encodeToString(Mockito.same(x509Encode))).thenThrow(new RuntimeException("error"));

        WriteFile writeFile = new WriteFileImpl();
        writeFile.writePublicKey("fileName", keys, log);
    }

    @Test
    public void testWriteCertKey() throws Exception {

        byte[] keys = new byte[0];
        byte[] x509Encode = new byte[0];

        PowerMockito.whenNew(FileWriter.class).withArguments("fileName").thenReturn(fileWriter);
        PowerMockito.whenNew(X509EncodedKeySpec.class).withArguments(keys).thenReturn(x509);
        PowerMockito.when(x509.getEncoded()).thenReturn(x509Encode);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.getMimeEncoder()).thenReturn(encoder);
        PowerMockito.when(encoder.encodeToString(Mockito.same(x509Encode))).thenReturn("body");

        WriteFile writeFile = new WriteFileImpl();
        writeFile.writeCertKey("fileName", keys, log);

        InOrder inOrder = Mockito.inOrder(fileWriter);

        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("-----BEGIN CERTIFICATE-----\n\r"));
        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("body"));
        inOrder.verify(fileWriter, Mockito.times(1)).write(Mockito.eq("\n\r-----END CERTIFICATE-----"));
    }

    @Test(expected = MojoExecutionException.class)
    public void testWriteCertKeyError() throws Exception {

        byte[] keys = new byte[0];
        byte[] x509Encode = new byte[0];

        PowerMockito.whenNew(FileWriter.class).withArguments("fileName").thenReturn(fileWriter);
        PowerMockito.whenNew(X509EncodedKeySpec.class).withArguments(keys).thenReturn(x509);
        PowerMockito.when(x509.getEncoded()).thenReturn(x509Encode);
        PowerMockito.mockStatic(Base64.class);
        PowerMockito.when(Base64.getMimeEncoder()).thenReturn(encoder);
        PowerMockito.when(encoder.encodeToString(Mockito.same(x509Encode))).thenThrow(new RuntimeException("error"));

        WriteFile writeFile = new WriteFileImpl();
        writeFile.writeCertKey("fileName", keys, log);
    }

}
