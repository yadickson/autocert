/*
 * Copyright (C) 2019 Yadickson Soto
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.github.yadickson.autocert;

import com.github.yadickson.autocert.security.Generator;
import com.github.yadickson.autocert.security.WriteFile;
import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

/**
 *
 * @author Yadickson Soto
 */
@RunWith(MockitoJUnitRunner.class)
public class AutoGeneratorTest {

    @Mock
    private MavenProject project;

    @Mock
    private Log log;

    @Mock
    private File outputDirectory;

    @Mock
    private Generator generator;

    @Mock
    private WriteFile writeFile;

    @Mock
    private PublicKey publicKey;

    @Mock
    private PrivateKey privateKey;

    @Test
    public void testExecute() throws Exception {
        AutoGenerator autoGen = new AutoGenerator();

        autoGen.setLog(log);

        autoGen.setProject(project);
        autoGen.setPubFile("pub.pem");
        autoGen.setKeyFile("key.pem");
        autoGen.setCertFile("cert.pem");
        autoGen.setAlgorithm("algorithm");
        autoGen.setSignature("signature");
        autoGen.setKeySize(1024);
        autoGen.setYears(4);
        autoGen.setIssuerDN("issuerDN");
        autoGen.setSubjectDN("subjectDN");
        autoGen.setDirectory("keys");
        autoGen.setOutputDirectory(outputDirectory);

        autoGen.setGenerator(generator);
        autoGen.setWriteFile(writeFile);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        String base = "target" + File.separator + "test-pom";

        byte[] key = new byte[0];
        byte[] pub = new byte[0];
        byte[] cert = new byte[0];

        Mockito.when(outputDirectory.getPath()).thenReturn(base);
        Mockito.when(outputDirectory.exists()).thenReturn(false);
        Mockito.when(outputDirectory.mkdirs()).thenReturn(true);

        Mockito.when(generator.createPair(Mockito.eq("algorithm"), Mockito.eq(1024), Mockito.same(log))).thenReturn(keyPair);
        Mockito.when(generator.getPrivateKey(Mockito.same(privateKey), Mockito.same(log))).thenReturn(key);
        Mockito.when(generator.getPublicKey(Mockito.same(publicKey), Mockito.same(log))).thenReturn(pub);
        Mockito.when(generator.getCertKey(Mockito.same(privateKey), Mockito.same(publicKey), Mockito.eq("signature"), Mockito.eq("issuerDN"), Mockito.eq("subjectDN"), Mockito.eq(4), Mockito.same(log))).thenReturn(cert);

        autoGen.execute();

        InOrder inOrder = Mockito.inOrder(log, generator, writeFile);

        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] PubFile: pub.pem"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] KeyFile: key.pem"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] CertFile: cert.pem"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Algorithm: algorithm"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Signature: signature"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] KeySize: 1024"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] IssuerDN: issuerDN"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] SubjectDN: subjectDN"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Years: 4"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Directory: keys"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Output: " + base));

        inOrder.verify(generator, Mockito.times(1)).createPair(Mockito.eq("algorithm"), Mockito.eq(1024), Mockito.same(log));
        inOrder.verify(generator, Mockito.times(1)).getPrivateKey(Mockito.same(privateKey), Mockito.same(log));
        inOrder.verify(generator, Mockito.times(1)).getPublicKey(Mockito.same(publicKey), Mockito.same(log));
        inOrder.verify(generator, Mockito.times(1)).getCertKey(Mockito.same(privateKey), Mockito.same(publicKey), Mockito.eq("signature"), Mockito.eq("issuerDN"), Mockito.eq("subjectDN"), Mockito.eq(4), Mockito.same(log));

        inOrder.verify(writeFile, Mockito.times(1)).writePrivateKey(Mockito.eq(base + File.separator + "keys" + File.separator + "key.pem"), Mockito.same(key), Mockito.same(log));
        inOrder.verify(writeFile, Mockito.times(1)).writePublicKey(Mockito.eq(base + File.separator + "keys" + File.separator + "pub.pem"), Mockito.same(pub), Mockito.same(log));
        inOrder.verify(writeFile, Mockito.times(1)).writeCertKey(Mockito.eq(base + File.separator + "keys" + File.separator + "cert.pem"), Mockito.same(cert), Mockito.same(log));

        Mockito.verify(outputDirectory, Mockito.times(1)).exists();
        Mockito.verify(outputDirectory, Mockito.times(1)).mkdirs();
    }

    @Test
    public void testExecuteDirectoryExist() throws Exception {
        AutoGenerator autoGen = new AutoGenerator();

        autoGen.setLog(log);

        autoGen.setProject(project);
        autoGen.setPubFile("pub.pem");
        autoGen.setKeyFile("key.pem");
        autoGen.setCertFile("cert.pem");
        autoGen.setAlgorithm("algorithm");
        autoGen.setSignature("signature");
        autoGen.setKeySize(1024);
        autoGen.setYears(4);
        autoGen.setIssuerDN("issuerDN");
        autoGen.setSubjectDN("subjectDN");
        autoGen.setDirectory("keys");
        autoGen.setOutputDirectory(outputDirectory);

        autoGen.setGenerator(generator);
        autoGen.setWriteFile(writeFile);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        String base = "target" + File.separator + "test-pom";

        byte[] key = new byte[0];
        byte[] pub = new byte[0];
        byte[] cert = new byte[0];

        Mockito.when(outputDirectory.getPath()).thenReturn(base);
        Mockito.when(outputDirectory.exists()).thenReturn(true);
        Mockito.when(outputDirectory.mkdirs()).thenReturn(false);

        Mockito.when(generator.createPair(Mockito.eq("algorithm"), Mockito.eq(1024), Mockito.same(log))).thenReturn(keyPair);
        Mockito.when(generator.getPrivateKey(Mockito.same(privateKey), Mockito.same(log))).thenReturn(key);
        Mockito.when(generator.getPublicKey(Mockito.same(publicKey), Mockito.same(log))).thenReturn(pub);
        Mockito.when(generator.getCertKey(Mockito.same(privateKey), Mockito.same(publicKey), Mockito.eq("signature"), Mockito.eq("issuerDN"), Mockito.eq("subjectDN"), Mockito.eq(4), Mockito.same(log))).thenReturn(cert);

        autoGen.execute();

        InOrder inOrder = Mockito.inOrder(log, generator, writeFile);

        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] PubFile: pub.pem"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] KeyFile: key.pem"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] CertFile: cert.pem"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Algorithm: algorithm"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Signature: signature"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] KeySize: 1024"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] IssuerDN: issuerDN"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] SubjectDN: subjectDN"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Years: 4"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Directory: keys"));
        inOrder.verify(log, Mockito.times(1)).info(Mockito.eq("[AutoGenerator] Output: " + base));

        inOrder.verify(generator, Mockito.times(1)).createPair(Mockito.eq("algorithm"), Mockito.eq(1024), Mockito.same(log));
        inOrder.verify(generator, Mockito.times(1)).getPrivateKey(Mockito.same(privateKey), Mockito.same(log));
        inOrder.verify(generator, Mockito.times(1)).getPublicKey(Mockito.same(publicKey), Mockito.same(log));
        inOrder.verify(generator, Mockito.times(1)).getCertKey(Mockito.same(privateKey), Mockito.same(publicKey), Mockito.eq("signature"), Mockito.eq("issuerDN"), Mockito.eq("subjectDN"), Mockito.eq(4), Mockito.same(log));

        inOrder.verify(writeFile, Mockito.times(1)).writePrivateKey(Mockito.eq(base + File.separator + "keys" + File.separator + "key.pem"), Mockito.same(key), Mockito.same(log));
        inOrder.verify(writeFile, Mockito.times(1)).writePublicKey(Mockito.eq(base + File.separator + "keys" + File.separator + "pub.pem"), Mockito.same(pub), Mockito.same(log));
        inOrder.verify(writeFile, Mockito.times(1)).writeCertKey(Mockito.eq(base + File.separator + "keys" + File.separator + "cert.pem"), Mockito.same(cert), Mockito.same(log));

        Mockito.verify(outputDirectory, Mockito.times(1)).exists();
        Mockito.verify(outputDirectory, Mockito.never()).mkdirs();
    }

    @Test(expected = MojoExecutionException.class)
    public void testExecuteError() throws Exception {
        AutoGenerator autoGen = new AutoGenerator();

        autoGen.setLog(log);

        autoGen.setProject(project);
        autoGen.setPubFile("pub.pem");
        autoGen.setKeyFile("key.pem");
        autoGen.setCertFile("cert.pem");
        autoGen.setAlgorithm("algorithm");
        autoGen.setSignature("signature");
        autoGen.setKeySize(1024);
        autoGen.setYears(4);
        autoGen.setIssuerDN("issuerDN");
        autoGen.setSubjectDN("subjectDN");
        autoGen.setDirectory("keys");
        autoGen.setOutputDirectory(outputDirectory);

        autoGen.setGenerator(generator);
        autoGen.setWriteFile(writeFile);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        String base = "target" + File.separator + "test-pom";

        byte[] key = new byte[0];
        byte[] pub = new byte[0];
        byte[] cert = new byte[0];

        Mockito.when(outputDirectory.getPath()).thenReturn(base);
        Mockito.when(outputDirectory.exists()).thenReturn(false);
        Mockito.when(outputDirectory.mkdirs()).thenReturn(false);

        Mockito.when(generator.createPair(Mockito.eq("algorithm"), Mockito.eq(1024), Mockito.same(log))).thenReturn(keyPair);
        Mockito.when(generator.getPrivateKey(Mockito.same(privateKey), Mockito.same(log))).thenReturn(key);
        Mockito.when(generator.getPublicKey(Mockito.same(publicKey), Mockito.same(log))).thenReturn(pub);
        Mockito.when(generator.getCertKey(Mockito.same(privateKey), Mockito.same(publicKey), Mockito.eq("signature"), Mockito.eq("issuerDN"), Mockito.eq("subjectDN"), Mockito.eq(4), Mockito.same(log))).thenReturn(cert);

        autoGen.execute();
    }

}
