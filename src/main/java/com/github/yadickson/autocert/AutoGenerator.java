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
import com.github.yadickson.autocert.security.GeneratorImpl;
import com.github.yadickson.autocert.security.WriteFile;
import com.github.yadickson.autocert.security.WriteFileImpl;
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
     * The Maven Project.
     */
    @Parameter(
            defaultValue = "${project}",
            readonly = true
    )
    private MavenProject project;

    /**
     * Public file name.
     */
    @Parameter(
            property = "autocert.pubFile",
            required = false,
            defaultValue = "pub.pem")
    private String pubFile;

    /**
     * Key file name.
     */
    @Parameter(
            property = "autocert.keyFile",
            required = false,
            defaultValue = "key.pem")
    private String keyFile;

    /**
     * Cert file name.
     */
    @Parameter(
            property = "autocert.certFile",
            required = false,
            defaultValue = "cert.pem")
    private String certFile;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.algorithm",
            required = false,
            defaultValue = "RSA")
    private String algorithm;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.keySize",
            required = false,
            defaultValue = "1024")
    private Integer keySize;

    /**
     * Signature.
     */
    @Parameter(
            property = "autocert.signature",
            required = false,
            defaultValue = "SHA256withRSA")
    private String signature;

    /**
     * Years validity.
     */
    @Parameter(
            property = "autocert.years",
            required = false,
            defaultValue = "10")
    private Integer years;

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
            defaultValue = "keys")
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
     * Generator.
     */
    private Generator generator = new GeneratorImpl();

    /**
     * Write file.
     */
    private WriteFile writeFile = new WriteFileImpl();

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
        getLog().info("[AutoGenerator] Years: " + years);
        getLog().info("[AutoGenerator] Directory: " + directory);
        getLog().info("[AutoGenerator] Output: " + outputDirectory.getPath());

        try {

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

            dir.mkdirs();

            Security.addProvider(new BouncyCastleProvider());

            String keyFilePath = basePath + keyFile;
            String pubFilePath = basePath + pubFile;
            String certFilePath = basePath + certFile;

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
                    pair.getPrivate(),
                    pair.getPublic(),
                    signature,
                    issuerDN,
                    subjectDN,
                    years,
                    getLog()
            );

            writeFile.writePrivateKey(keyFilePath, key, getLog());
            writeFile.writePublicKey(pubFilePath, pub, getLog());
            writeFile.writeCertKey(certFilePath, cert, getLog());

        } catch (RuntimeException | MojoExecutionException ex) {
            getLog().error(ex.getMessage(), ex);
            throw new MojoExecutionException("Fail cert generator");
        }
    }

    /**
     * Setter maven project only for test.
     *
     * @param pproject the project to set
     */
    public void setProject(final MavenProject pproject) {
        this.project = pproject;
    }

    /**
     * Setter public file only for test.
     *
     * @param ppubFile the pubFile to set
     */
    public void setPubFile(final String ppubFile) {
        this.pubFile = ppubFile;
    }

    /**
     * Setter private file only for test.
     *
     * @param pkeyFile the keyFile to set
     */
    public void setKeyFile(final String pkeyFile) {
        this.keyFile = pkeyFile;
    }

    /**
     * Setter certificate file only for test.
     *
     * @param pcertFile the certFile to set
     */
    public void setCertFile(final String pcertFile) {
        this.certFile = pcertFile;
    }

    /**
     * Setter algorithm only for test.
     *
     * @param palgorithm the algorithm to set
     */
    public void setAlgorithm(final String palgorithm) {
        this.algorithm = palgorithm;
    }

    /**
     * Setter key size only for test.
     *
     * @param pkeySize the keySize to set
     */
    public void setKeySize(final Integer pkeySize) {
        this.keySize = pkeySize;
    }

    /**
     * Setter signature only for test.
     *
     * @param psignature the signature to set
     */
    public void setSignature(final String psignature) {
        this.signature = psignature;
    }

    /**
     * Setter years only for test.
     *
     * @param pyears the years to set
     */
    public void setYears(final Integer pyears) {
        this.years = pyears;
    }

    /**
     * Setter issuerDN only for test.
     *
     * @param pissuerDN the issuerDN to set
     */
    public void setIssuerDN(final String pissuerDN) {
        this.issuerDN = pissuerDN;
    }

    /**
     * Setter subjectDN only for test.
     *
     * @param psubjectDN the subjectDN to set
     */
    public void setSubjectDN(final String psubjectDN) {
        this.subjectDN = psubjectDN;
    }

    /**
     * Setter directory only for test.
     *
     * @param pdirectory the directory to set
     */
    public void setDirectory(final String pdirectory) {
        this.directory = pdirectory;
    }

    /**
     * Setter directory only for test.
     *
     * @param poutputDirectory the outputDirectory to set
     */
    public void setOutputDirectory(final File poutputDirectory) {
        this.outputDirectory = poutputDirectory;
    }

    /**
     * Setter generator only for test.
     *
     * @param pgenerator the generator to set
     */
    public void setGenerator(final Generator pgenerator) {
        this.generator = pgenerator;
    }

    /**
     * Setter writeFile only for test.
     *
     * @param pwriteFile the writeFile to set
     */
    public void setWriteFile(final WriteFile pwriteFile) {
        this.writeFile = pwriteFile;
    }

}
