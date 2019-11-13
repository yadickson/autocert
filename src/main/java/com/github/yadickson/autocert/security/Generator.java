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
package com.github.yadickson.autocert.security;

import java.math.BigInteger;
import org.apache.maven.plugin.MojoExecutionException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import org.apache.maven.plugin.logging.Log;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * Pair generate certificates.
 *
 * @author Yadickson Soto
 */
public final class Generator {

    private final static String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    public KeyPair createPair(
            final String algorithm,
            final Integer keySize,
            final Log log
    ) throws MojoExecutionException {

        try {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    algorithm,
                    PROVIDER
            );

            switch (algorithm) {
                case "RSA":
                    kpg.initialize(keySize, new SecureRandom());
                    break;
                case "EC":
                case "ECDSA":
                case "ECDH":
                    ECGenParameterSpec spec;
                    spec = new ECGenParameterSpec("secp" + keySize + "r1");
                    kpg.initialize(spec, new SecureRandom());
                    break;
                default:
                    throw new MojoExecutionException(
                            "The algorithm " + algorithm + " not supported"
                    );
            }

            return kpg.generateKeyPair();

        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException(
                    "Fail pair generator",
                    ex
            );
        }
    }

    public byte[] getPrivateKey(
            final PrivateKey privateKey,
            final Log log
    ) throws MojoExecutionException {
        return getPrivateKeySpec(privateKey, log).getEncoded();
    }

    public byte[] getPublicKey(
            final PublicKey publicKey,
            final Log log
    ) throws MojoExecutionException {
        return getPublicKeySpec(publicKey, log).getEncoded();
    }

    public PKCS8EncodedKeySpec getPrivateKeySpec(
            final PrivateKey privateKey,
            final Log log
    ) throws MojoExecutionException {

        try {

            final PKCS8EncodedKeySpec keySpec;
            keySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
            return keySpec;

        } catch (RuntimeException ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException(
                    "Fail to get private key",
                    ex
            );
        }
    }

    public X509EncodedKeySpec getPublicKeySpec(
            final PublicKey publicKey,
            final Log log
    ) throws MojoExecutionException {

        try {

            final X509EncodedKeySpec keySpec;
            keySpec = new X509EncodedKeySpec(publicKey.getEncoded());
            return keySpec;

        } catch (RuntimeException ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException(
                    "Fail to get public key",
                    ex
            );
        }
    }

    public byte[] getCertKey(
            final PublicKey publicKey,
            final PrivateKey privateKey,
            final String signature,
            final String issuerDN,
            final String subjectDN,
            final Integer yearsValidity,
            final Log log
    ) throws MojoExecutionException {

        try {

            X509V3CertificateGenerator certGen;
            certGen = new X509V3CertificateGenerator();

            long millis = System.currentTimeMillis();
            long before = millis - 24 * 60 * 60 * 1000;
            long to = millis + yearsValidity * 365 * 24 * 60 * 60 * 1000;

            certGen.setSerialNumber(BigInteger.valueOf(millis));
            certGen.setIssuerDN(new X509Name(issuerDN));
            certGen.setSubjectDN(new X509Name(subjectDN));

            certGen.setNotBefore(new Date(before));
            certGen.setNotAfter(new Date(to));

            certGen.setPublicKey(publicKey);
            certGen.setSignatureAlgorithm(signature);
            certGen.addExtension(
                    X509Extensions.ExtendedKeyUsage,
                    true,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping)
            );

            X509Certificate cert = certGen.generate(
                    privateKey,
                    PROVIDER,
                    new SecureRandom()
            );

            return cert.getEncoded();

        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException(
                    "Fail to get certificate key",
                    ex
            );
        }
    }

    public SecretKey getSecretKey(
            final PrivateKey privateKey,
            final PublicKey publicKey,
            final Log log
    ) throws MojoExecutionException {

        try {

            KeyAgreement keyAgreement;
            String algorithm;

            switch (privateKey.getAlgorithm()) {
                case "EC":
                case "ECDSA":
                case "ECDH":
                    algorithm = "ECDH";
                    break;
                default:
                    throw new MojoExecutionException(
                            "The algorithm " + privateKey.getAlgorithm()
                            + " not supported"
                    );
            }

            keyAgreement = KeyAgreement.getInstance(
                    algorithm,
                    PROVIDER
            );

            keyAgreement.init(privateKey, new SecureRandom());
            keyAgreement.doPhase(publicKey, true);

            return keyAgreement.generateSecret("AES");

        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException(
                    "Fail to get shared secret key",
                    ex
            );
        }
    }

}
