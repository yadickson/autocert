/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.yadickson.autocert.security;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import org.apache.commons.codec.binary.Base64;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;

/**
 *
 * @author Yadickson Soto
 */
@RunWith(MockitoJUnitRunner.class)
public class GeneratorTest {

    @InjectMocks
    private GeneratorImpl manager;

    @Mock
    private Log log;

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGeneratePar_RSA_1024() throws Exception {

        KeyPair result = manager.createPair("RSA", 1024, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("RSA", privKey.getAlgorithm());
        Assert.assertEquals("RSA", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withRSA", "cn=domain", "cn=main", 1, log));
    }

    @Test(expected = MojoExecutionException.class)
    public void testGetPrivateKeyFromNull() throws Exception {

        manager.getPrivateKey(null, log);
    }

    @Test(expected = MojoExecutionException.class)
    public void testGetPublicKeyFromNull() throws Exception {

        manager.getPublicKey(null, log);
    }

    @Test(expected = MojoExecutionException.class)
    public void testGetCertKeyFromNull() throws Exception {

        manager.getCertKey(null, null, null, null, null, null, log);
    }

    @Test
    public void testGeneratePar_RSA_4096() throws Exception {

        KeyPair result = manager.createPair("RSA", 4096, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("RSA", privKey.getAlgorithm());
        Assert.assertEquals("RSA", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withRSA", "cn=domain", "cn=main", 1, log));
    }

    @Test(expected = MojoExecutionException.class)
    public void testGeneratePar_XXX_4096_Error() throws MojoExecutionException {

        manager.createPair("XXX", 4096, log);
    }

    @Test(expected = MojoExecutionException.class)
    public void testGeneratePar_DSA_4096_Error() throws MojoExecutionException {

        manager.createPair("DSA", 4096, log);
    }

    @Test
    public void testGeneratePar_EC_256() throws Exception {

        KeyPair result = manager.createPair("EC", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withECDSA", "cn=domain", "cn=main", 1, log));
    }

    @Test
    public void testGeneratePar_EC_384() throws Exception {

        KeyPair result = manager.createPair("EC", 384, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withECDSA", "cn=domain", "cn=main", 1, log));
    }

    @Test
    public void testGeneratePar_EC_521() throws Exception {

        KeyPair result = manager.createPair("EC", 521, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withECDSA", "cn=domain", "cn=main", 1, log));
    }

    @Test(expected = MojoExecutionException.class)
    public void testGeneratePar_EC_Error() throws Exception {

        manager.createPair("EC", 1024, log);
    }

    @Test
    public void testGeneratePar_ECDSA_256() throws Exception {

        KeyPair result = manager.createPair("ECDSA", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("ECDSA", privKey.getAlgorithm());
        Assert.assertEquals("ECDSA", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withECDSA", "cn=domain", "cn=main", 1, log));
    }

    @Test
    public void testGeneratePar_ECDH_256() throws Exception {

        KeyPair result = manager.createPair("ECDH", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("ECDH", privKey.getAlgorithm());
        Assert.assertEquals("ECDH", pubKey.getAlgorithm());

        Assert.assertNotNull(manager.getPublicKey(pubKey, log));
        Assert.assertNotNull(manager.getPrivateKey(privKey, log));
        Assert.assertNotNull(manager.getCertKey(pubKey, privKey, "SHA256withECDSA", "cn=domain", "cn=main", 1, log));
    }

    @Test
    public void testSign_And_Verify_RSA_4096() throws Exception {

        KeyPair result = manager.createPair("RSA", 1024, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("RSA", privKey.getAlgorithm());
        Assert.assertEquals("RSA", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withRSA", "BC");
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withRSA", "BC");
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testSign_And_Verify_EC_256() throws Exception {

        KeyPair result = manager.createPair("EC", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testSign_And_Verify_ECDSA_256() throws Exception {

        KeyPair result = manager.createPair("ECDSA", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("ECDSA", privKey.getAlgorithm());
        Assert.assertEquals("ECDSA", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testCrypt_And_Decrypt_EC_256() throws Exception {

        KeyPair result = manager.createPair("EC", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        SecretKey secretKeyA = manager.getSecretKey(privKey, pubKey, log);
        SecretKey secretKeyB = manager.getSecretKey(privKey, pubKey, log);

        Assert.assertNotNull(secretKeyA);
        Assert.assertNotNull(secretKeyB);

        String plainText = "Abcd1234.,";
        byte[] process = plainText.getBytes("UTF-8");

        byte[] iv = new SecureRandom().generateSeed(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        //crypt
        Cipher cryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cryptCipher.init(Cipher.ENCRYPT_MODE, secretKeyA, ivSpec);

        byte[] encrypt = new byte[cryptCipher.getOutputSize(process.length)];
        int encryptLength = cryptCipher.update(process, 0, process.length, encrypt, 0);
        cryptCipher.doFinal(encrypt, encryptLength);

        Assert.assertNotNull(encrypt);

        String sign = Base64.encodeBase64String(encrypt);
        Assert.assertNotNull(sign);

        //decrypt
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeyB, ivSpec);

        byte[] decrypt = new byte[decryptCipher.getOutputSize(encrypt.length)];
        int decryptLength = decryptCipher.update(encrypt, 0, encrypt.length, decrypt, 0);
        decryptCipher.doFinal(decrypt, decryptLength);

        Assert.assertNotNull(decrypt);

        String resultText = new String(decrypt);

        Assert.assertEquals(plainText.trim(), resultText.trim());
    }

    @Test
    public void testCrypt_And_Decrypt_ECDH_256() throws Exception {

        KeyPair result = manager.createPair("ECDH", 256, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("ECDH", privKey.getAlgorithm());
        Assert.assertEquals("ECDH", pubKey.getAlgorithm());

        SecretKey secretKeyA = manager.getSecretKey(privKey, pubKey, log);
        SecretKey secretKeyB = manager.getSecretKey(privKey, pubKey, log);

        Assert.assertNotNull(secretKeyA);
        Assert.assertNotNull(secretKeyB);

        String plainText = "Abcd1234.,";
        byte[] process = plainText.getBytes("UTF-8");

        byte[] iv = new SecureRandom().generateSeed(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        //crypt
        Cipher cryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cryptCipher.init(Cipher.ENCRYPT_MODE, secretKeyA, ivSpec);

        byte[] encrypt = new byte[cryptCipher.getOutputSize(process.length)];
        int encryptLength = cryptCipher.update(process, 0, process.length, encrypt, 0);
        cryptCipher.doFinal(encrypt, encryptLength);

        Assert.assertNotNull(encrypt);

        String sign = Base64.encodeBase64String(encrypt);
        Assert.assertNotNull(sign);

        //decrypt
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeyB, ivSpec);

        byte[] decrypt = new byte[decryptCipher.getOutputSize(encrypt.length)];
        int decryptLength = decryptCipher.update(encrypt, 0, encrypt.length, decrypt, 0);
        decryptCipher.doFinal(decrypt, decryptLength);

        Assert.assertNotNull(decrypt);

        String resultText = new String(decrypt);

        Assert.assertEquals(plainText.trim(), resultText.trim());
    }

    @Test(expected = MojoExecutionException.class)
    public void testCrypt_And_Decrypt_RSA_2048() throws Exception {

        KeyPair result = manager.createPair("RSA", 2048, log);
        Assert.assertNotNull(result);

        PrivateKey privKey = result.getPrivate();
        PublicKey pubKey = result.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("RSA", privKey.getAlgorithm());
        Assert.assertEquals("RSA", pubKey.getAlgorithm());

        manager.getSecretKey(privKey, pubKey, log);
    }
}
