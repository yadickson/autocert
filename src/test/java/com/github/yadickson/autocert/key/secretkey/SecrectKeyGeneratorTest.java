package com.github.yadickson.autocert.key.secretkey;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
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
import com.github.yadickson.autocert.key.secrectkey.SecretKeyGenerator;
import com.github.yadickson.autocert.key.secrectkey.SecretKeyGeneratorException;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.provider.ProviderDecorator;

@RunWith(MockitoJUnitRunner.class)
public class SecrectKeyGeneratorTest {

    private SecretKeyGenerator generator;

    private AlgorithmMapper algorithmMapper;

    private ProviderDecorator provider;

    private KeyPairGenerator keyPairGenerator;

    @Mock
    private Parameters parametersPluginMock;

    @Before
    public void setUp() {
        algorithmMapper = new AlgorithmMapper();
        generator = new SecretKeyGenerator(algorithmMapper);

        provider = new ProviderDecorator(new ProviderConfiguration());
        keyPairGenerator = new KeyPairGenerator(new AlgorithmMapper(), new KeyPairInitializeFactory());
    }

    @After
    public void setDown() throws IOException {
        provider.close();
    }

    @Test
    public void testSign_And_Verify_RSA_4096() throws Exception {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(4096);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("RSA", privKey.getAlgorithm());
        Assert.assertEquals("RSA", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withRSA", provider.getName());
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withRSA", provider.getName());
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testSign_And_Verify_EC_256() throws Exception {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withECDSA", provider.getName());
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withECDSA", provider.getName());
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testSign_And_Verify_ECDH_256() throws Exception {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("ECDH", privKey.getAlgorithm());
        Assert.assertEquals("ECDH", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withECDSA", provider.getName());
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withECDSA", provider.getName());
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testSign_And_Verify_ECDSA_256() throws Exception {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("ECDSA", privKey.getAlgorithm());
        Assert.assertEquals("ECDSA", pubKey.getAlgorithm());

        String plainText = "Abcd1234.,";

        //sign
        Signature rsaSign = Signature.getInstance("SHA256withECDSA", provider.getName());
        rsaSign.initSign(privKey);
        rsaSign.update(plainText.getBytes("UTF-8"));
        byte[] signature = rsaSign.sign();

        Assert.assertNotNull(signature);

        String sign = Base64.encodeBase64String(signature);
        Assert.assertNotNull(sign);

        //verify
        Signature rsaVerify = Signature.getInstance("SHA256withECDSA", provider.getName());
        rsaVerify.initVerify(pubKey);
        rsaVerify.update(plainText.getBytes("UTF-8"));
        Assert.assertTrue(rsaVerify.verify(signature));
    }

    @Test
    public void testCrypt_And_Decrypt_EC_256() throws Exception {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("EC");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("EC", privKey.getAlgorithm());
        Assert.assertEquals("EC", pubKey.getAlgorithm());

        SecretKey secretKeyA = generator.execute(provider, keyPair);
        SecretKey secretKeyB = generator.execute(provider, keyPair);

        Assert.assertNotNull(secretKeyA);
        Assert.assertNotNull(secretKeyB);

        String plainText = "Abcd1234.,";
        byte[] process = plainText.getBytes("UTF-8");

        byte[] iv = new SecureRandom().generateSeed(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        //crypt
        Cipher cryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider.getName());
        cryptCipher.init(Cipher.ENCRYPT_MODE, secretKeyA, ivSpec);

        byte[] encrypt = new byte[cryptCipher.getOutputSize(process.length)];
        int encryptLength = cryptCipher.update(process, 0, process.length, encrypt, 0);
        cryptCipher.doFinal(encrypt, encryptLength);

        Assert.assertNotNull(encrypt);

        String sign = Base64.encodeBase64String(encrypt);
        Assert.assertNotNull(sign);

        //decrypt
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider.getName());
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

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("ECDH");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(256);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertEquals("ECDH", privKey.getAlgorithm());
        Assert.assertEquals("ECDH", pubKey.getAlgorithm());

        SecretKey secretKeyA = generator.execute(provider, keyPair);
        SecretKey secretKeyB = generator.execute(provider, keyPair);

        Assert.assertNotNull(secretKeyA);
        Assert.assertNotNull(secretKeyB);

        String plainText = "Abcd1234.,";
        byte[] process = plainText.getBytes("UTF-8");

        byte[] iv = new SecureRandom().generateSeed(16);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        //crypt
        Cipher cryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider.getName());
        cryptCipher.init(Cipher.ENCRYPT_MODE, secretKeyA, ivSpec);

        byte[] encrypt = new byte[cryptCipher.getOutputSize(process.length)];
        int encryptLength = cryptCipher.update(process, 0, process.length, encrypt, 0);
        cryptCipher.doFinal(encrypt, encryptLength);

        Assert.assertNotNull(encrypt);

        String sign = Base64.encodeBase64String(encrypt);
        Assert.assertNotNull(sign);

        //decrypt
        Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", provider.getName());
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeyB, ivSpec);

        byte[] decrypt = new byte[decryptCipher.getOutputSize(encrypt.length)];
        int decryptLength = decryptCipher.update(encrypt, 0, encrypt.length, decrypt, 0);
        decryptCipher.doFinal(decrypt, decryptLength);

        Assert.assertNotNull(decrypt);

        String resultText = new String(decrypt);

        Assert.assertEquals(plainText.trim(), resultText.trim());
    }

    @Test(expected = SecretKeyGeneratorException.class)
    public void testCrypt_And_Decrypt_RSA_2048() throws Exception {

        Mockito.when(parametersPluginMock.getAlgorithm()).thenReturn("RSA");
        Mockito.when(parametersPluginMock.getKeySize()).thenReturn(2048);

        KeyPair keyPair = keyPairGenerator.execute(provider, parametersPluginMock);

        Assert.assertNotNull(keyPair);

        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        Assert.assertNotNull(privKey);
        Assert.assertNotNull(pubKey);

        Assert.assertEquals("RSA", privKey.getAlgorithm());
        Assert.assertEquals("RSA", pubKey.getAlgorithm());

        generator.execute(provider, keyPair);
    }

}
