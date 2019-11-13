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

import java.util.Base64;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;

/**
 * Class to write certificate's files.
 *
 * @author Yadickson Soto
 */
public final class WriteFile {

    public void writePrivateKey(
            final String filePath,
            final byte[] key,
            final Log log
    ) throws MojoExecutionException {

        try (Writer keyWriter = new FileWriter(filePath);) {

            final PKCS8EncodedKeySpec keySpec;
            keySpec = new PKCS8EncodedKeySpec(key);

            keyWriter.write("-----BEGIN PRIVATE KEY-----\n\r");
            keyWriter.write(Base64.getMimeEncoder().encodeToString(keySpec.getEncoded()));
            keyWriter.write("\n\r-----END PRIVATE KEY-----");

        } catch (RuntimeException | IOException ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException("Fail private generator key");
        }
    }

    public void writePublicKey(
            final String filePath,
            final byte[] pub,
            final Log log
    ) throws MojoExecutionException {

        try (Writer pubWriter = new FileWriter(filePath)) {

            final X509EncodedKeySpec keySpec;
            keySpec = new X509EncodedKeySpec(pub);

            pubWriter.write("-----BEGIN PUBLIC KEY-----\n\r");
            pubWriter.write(Base64.getMimeEncoder().encodeToString(keySpec.getEncoded()));
            pubWriter.write("\n\r-----END PUBLIC KEY-----");

        } catch (RuntimeException | IOException ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException("Fail public generator key");
        }
    }

    public void writeCertKey(
            final String filePath,
            final byte[] cert,
            final Log log
    ) throws MojoExecutionException {

        try (Writer pubWriter = new FileWriter(filePath)) {

            final X509EncodedKeySpec keySpec;
            keySpec = new X509EncodedKeySpec(cert);

            pubWriter.write("-----BEGIN CERTIFICATE-----\n\r");
            pubWriter.write(Base64.getMimeEncoder().encodeToString(keySpec.getEncoded()));
            pubWriter.write("\n\r-----END CERTIFICATE-----");

        } catch (RuntimeException | IOException ex) {
            log.error(ex.getMessage(), ex);
            throw new MojoExecutionException("Fail public generator cert key");
        }
    }
}
