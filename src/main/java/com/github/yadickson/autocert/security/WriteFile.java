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
import org.apache.maven.plugin.logging.Log;

/**
 * Interface to write certificate's files.
 *
 * @author Yadickson Soto
 */
public interface WriteFile {

    /**
     * Write private file.
     *
     * @param filePath file path name.
     * @param key array byte private key.
     * @param log logger
     * @throws MojoExecutionException if error.
     */
    void writePrivateKey(
            final String filePath,
            final byte[] key,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Write public file.
     *
     * @param filePath file path name.
     * @param pub array byte public key.
     * @param log logger
     * @throws MojoExecutionException if error.
     */
    void writePublicKey(
            final String filePath,
            final byte[] pub,
            final Log log
    ) throws MojoExecutionException;

    /**
     * Write certificate file.
     *
     * @param filePath file path name.
     * @param cert array byte certificate key.
     * @param log logger
     * @throws MojoExecutionException if error.
     */
    void writeCertKey(
            final String filePath,
            final byte[] cert,
            final Log log
    ) throws MojoExecutionException;
}
