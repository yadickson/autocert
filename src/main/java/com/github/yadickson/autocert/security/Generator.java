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

import org.apache.maven.plugin.MojoExecutionException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import org.apache.maven.plugin.logging.Log;

/**
 * Pair generate certificates interface.
 *
 * @author Yadickson Soto
 */
public interface Generator {

    /**
     * Create pair certificates.
     *
     * @param algorithm algorithm name.
     * @param keySize key size.
     * @param log logger.
     * @return key pair.
     * @throws MojoExecutionException if error.
     */
    KeyPair createPair(
            final String algorithm,
            final Integer keySize,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Getter private key.
     *
     * @param privateKey private key.
     * @param log logger.
     * @return byte array private key.
     * @throws MojoExecutionException if error.
     */
    byte[] getPrivateKey(
            final PrivateKey privateKey,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Getter public key.
     *
     * @param publicKey public key.
     * @param log logger.
     * @return byte array public key.
     * @throws MojoExecutionException if error.
     */
    byte[] getPublicKey(
            final PublicKey publicKey,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Getter private key.
     *
     * @param privateKey private key.
     * @param log logger.
     * @return byte array private key.
     * @throws MojoExecutionException if error.
     */
    PKCS8EncodedKeySpec getPrivateKeySpec(
            final PrivateKey privateKey,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Getter public key.
     *
     * @param publicKey public key.
     * @param log logger.
     * @return byte array public key.
     * @throws MojoExecutionException if error.
     */
    X509EncodedKeySpec getPublicKeySpec(
            final PublicKey publicKey,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Create certificate key.
     *
     * @param publicKey public key.
     * @param privateKey private key.
     * @param signature signature algorithm.
     * @param issuerDN issuer DN.
     * @param subjectDN subject DN.
     * @param years years validity
     * @param log logger.
     * @return certificate key.
     * @throws MojoExecutionException if error.
     */
    byte[] getCertKey(
            final PrivateKey privateKey,
            final PublicKey publicKey,
            final String signature,
            final String issuerDN,
            final String subjectDN,
            final Integer years,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Create AES secret key.
     *
     * @param privateKey private key.
     * @param publicKey public key.
     * @param log logger.
     * @return aes secret key.
     * @throws MojoExecutionException if error.
     */
    SecretKey getSecretKey(
            final PrivateKey privateKey,
            final PublicKey publicKey,
            final Log log
    ) throws MojoExecutionException;

}
