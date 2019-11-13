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
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.security.KeyPair;
import java.security.Security;
import org.apache.maven.model.Resource;

import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Maven plugin to generate certificates in compilation time.
 *
 * @author Yadickson Soto
 */
@Mojo(name = "generator",
        threadSafe = true,
        defaultPhase = LifecyclePhase.GENERATE_RESOURCES,
        requiresProject = true)
public final class AutoGenerator extends AbstractMojo {

    /**
     * Maven project link.
     */
    @Parameter(defaultValue = "${project}", readonly = true)
    private MavenProject project;

    /**
     * Public file name.
     */
    @Parameter(
            property = "autocert.pubFile",
            required = true)
    private String pubFile;

    /**
     * Key file name.
     */
    @Parameter(
            property = "autocert.keyFile",
            required = true)
    private String keyFile;

    /**
     * Cert file name.
     */
    @Parameter(
            property = "autocert.certFile",
            required = true)
    private String certFile;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.algorithm",
            required = true)
    private String algorithm;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.keySize",
            required = true)
    private Integer keySize;

    /**
     * Signature.
     */
    @Parameter(
            property = "autocert.signature",
            required = true)
    private String signature;

    /**
     * Years validity.
     */
    @Parameter(
            property = "autocert.yearsValidity",
            required = false,
            defaultValue = "1")
    private Integer yearsValidity;

    /**
     * Issuer DN.
     */
    @Parameter(
            property = "autocert.issuerDN",
            required = false,
            defaultValue = "cn=domain")
    private String issuerDN;

    /**
     * Subject DN.
     */
    @Parameter(
            property = "autocert.subjectDN",
            required = false,
            defaultValue = "cn=main")
    private String subjectDN;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.directory",
            required = false,
            defaultValue = "./")
    private String directory;

    /**
     * Output resource directory.
     */
    @Parameter(
            defaultValue = "${project.build.directory}/generated-resources",
            readonly = true,
            required = false)
    private File outputDirectory;

    /**
     * Maven execute method.
     *
     * @throws MojoExecutionException Launch if the generation process throws an
     * error
     */
    @Override
    public void execute() throws MojoExecutionException {

        getLog().info("[AutoGenerator] PubFile: " + pubFile);
        getLog().info("[AutoGenerator] KeyFile: " + keyFile);
        getLog().info("[AutoGenerator] CertFile: " + certFile);
        getLog().info("[AutoGenerator] Algorithm: " + algorithm);
        getLog().info("[AutoGenerator] Signature: " + signature);
        getLog().info("[AutoGenerator] KeySize: " + keySize);
        getLog().info("[AutoGenerator] IssuerDN: " + issuerDN);
        getLog().info("[AutoGenerator] SubjectDN: " + subjectDN);
        getLog().info("[AutoGenerator] YearsValidity: " + yearsValidity);
        getLog().info("[AutoGenerator] Directory: " + directory);
        getLog().info("[AutoGenerator] Output: " + outputDirectory.getPath());

        if (!outputDirectory.exists() && !outputDirectory.mkdirs()) {
            throw new MojoExecutionException(
                    "Fail make " + outputDirectory + " directory."
            );
        }

        Resource resource = new Resource();
        resource.setDirectory(outputDirectory.getPath());
        project.addResource(resource);

        String basePath = outputDirectory.getPath()
                + File.separator
                + directory
                + File.separator;

        File dir = new File(basePath);

        if (!dir.exists() && !dir.mkdirs()) {
            throw new MojoExecutionException(
                    "Fail make " + basePath + " directory."
            );
        }

        try {

            Security.addProvider(new BouncyCastleProvider());

            String keyFilePath = basePath + keyFile;
            String pubFilePath = basePath + pubFile;
            String certFilePath = basePath + certFile;

            Generator generator = new Generator();
            WriteFile writeFile = new WriteFile();

            final KeyPair pair = generator.createPair(
                    algorithm,
                    keySize,
                    getLog()
            );

            byte[] key = generator.getPrivateKey(
                    pair.getPrivate(),
                    getLog()
            );

            byte[] pub = generator.getPublicKey(
                    pair.getPublic(),
                    getLog()
            );

            byte[] cert = generator.getCertKey(
                    pair.getPublic(),
                    pair.getPrivate(),
                    signature,
                    issuerDN,
                    subjectDN,
                    yearsValidity,
                    getLog()
            );

            writeFile.writePrivateKey(keyFilePath, key, getLog());
            writeFile.writePublicKey(pubFilePath, pub, getLog());
            writeFile.writeCertKey(certFilePath, cert, getLog());

        } catch (RuntimeException ex) {
            getLog().error(ex.getMessage(), ex);
            throw new MojoExecutionException("Fail cert generator");
        }
    }

}
