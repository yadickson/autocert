/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert;

import java.io.File;
import java.util.Optional;

import javax.inject.Inject;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import com.github.yadickson.autocert.directory.DirectoryBuilder;
import com.github.yadickson.autocert.key.KeysGenerator;
import com.github.yadickson.autocert.key.KeysResponse;
import com.github.yadickson.autocert.parameters.InputInformation;
import com.github.yadickson.autocert.parameters.OutputInformation;
import com.github.yadickson.autocert.parameters.Parameters;
import com.github.yadickson.autocert.writer.FilesGenerator;

/**
 * Maven plugin to generate certificates in compilation time.
 *
 * @author Yadickson Soto
 */
@Mojo(name = "generator",
        threadSafe = true,
        defaultPhase = LifecyclePhase.GENERATE_RESOURCES,
        requiresProject = true)
public final class GeneratorPlugin extends AbstractMojo {

    /**
     * The Maven Project.
     */
    @Parameter(
            defaultValue = "${project}",
            readonly = true
    )
    private MavenProject mavenProject;

    /**
     * Public file name.
     */
    @Parameter(
            property = "autocert.pubFile",
            alias = "pubFile",
            required = false,
            defaultValue = "pub.pem")
    private String pubFilename;

    /**
     * Key file name.
     */
    @Parameter(
            property = "autocert.keyFile",
            alias = "keyFile",
            required = false,
            defaultValue = "key.pem")
    private String keyFilename;

    /**
     * Cert file name.
     */
    @Parameter(
            property = "autocert.certFile",
            alias = "certFile",
            required = false,
            defaultValue = "cert.pem")
    private String certFilename;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.algorithm",
            alias = "algorithm",
            required = false,
            defaultValue = "RSA")
    private String algorithm;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.keySize",
            alias = "keySize",
            required = false,
            defaultValue = "1024")
    private Integer keySize;

    /**
     * Signature.
     */
    @Parameter(
            property = "autocert.signature",
            alias = "signature",
            required = false,
            defaultValue = "SHA256withRSA")
    private String signature;

    /**
     * Years validity.
     */
    @Parameter(
            property = "autocert.years",
            alias = "years",
            required = false,
            defaultValue = "10")
    private Integer years;

    /**
     * Issuer DN.
     */
    @Parameter(
            property = "autocert.issuer",
            alias = "issuer",
            required = false,
            defaultValue = "domain")
    private String issuer;

    /**
     * Subject DN.
     */
    @Parameter(
            property = "autocert.subject",
            alias = "subject",
            required = false,
            defaultValue = "main")
    private String subject;

    /**
     * Directory folder name.
     */
    @Parameter(
            property = "autocert.directoryName",
            alias = "directoryName",
            required = false,
            defaultValue = "keys")
    private String directoryName;

    /**
     * Output resource directory.
     */
    @Parameter(
            property = "autocert.outputDirectory",
            alias = "outputDirectory",
            required = false,
            defaultValue = "${project.build.directory}/generated-resources")
    private String outputDirectory;

    private InputInformation inputInformation;
    private OutputInformation outputInformation;
    private Parameters parameters;

    /**
     * All keys generator.
     */
    private final KeysGenerator keysGenerator;

    /**
     * All files generator.
     */
    private final FilesGenerator filesGenerator;

    /**
     * Directory builder.
     */
    private final DirectoryBuilder directoryBuilder;

    /**
     * Maven custom resource.
     */
    private final CustomResource customResource;

    /**
     * Keys response from keys generator.
     */
    private KeysResponse keysResponse;

    @Inject
    public GeneratorPlugin(
            final KeysGenerator keysGenerator,
            final FilesGenerator filesGenerator,
            final DirectoryBuilder directoryBuilder,
            final CustomResource customResource
    ) {
        this.keysGenerator = keysGenerator;
        this.filesGenerator = filesGenerator;
        this.directoryBuilder = directoryBuilder;
        this.customResource = customResource;
    }

    /**
     * Maven execute method.
     *
     * @throws MojoExecutionException Launch if the generation process throws an
     * error
     */
    @Override
    public void execute() throws MojoExecutionException {

        try {

            makeParameters();
            printParameters();
            generate();

        } catch (RuntimeException ex) {
            getLog().error(ex.getMessage(), ex);
            throw new MojoExecutionException("Execute error", ex);
        }
    }

    private void makeParameters() {
        parameters = Optional.ofNullable(parameters).orElse(buildParameters());
    }

    private Parameters buildParameters() {
        makeInputInformation();
        makeOutputInformation();
        return new Parameters(inputInformation, outputInformation);
    }

    private void makeInputInformation() {
        inputInformation = new InputInformation.Builder()
                .algorithm(algorithm)
                .keySize(keySize)
                .signature(signature)
                .years(years)
                .issuer(issuer)
                .subject(subject)
                .build();
    }

    private void makeOutputInformation() {
        outputInformation = new OutputInformation.Builder()
                .pubFilename(pubFilename)
                .keyFilename(keyFilename)
                .certFilename(certFilename)
                .directoryName(directoryName)
                .outputDirectory(outputDirectory)
                .build();
    }

    private void printParameters() {
        printInputInformation();
        printOutputInformation();
    }

    private void printInputInformation() {

        getLog().info("[Generator] Algorithm: " + parameters.getInput().getAlgorithm());
        getLog().info("[Generator] Signature: " + parameters.getInput().getSignature());
        getLog().info("[Generator] KeySize: " + parameters.getInput().getKeySize());
        getLog().info("[Generator] Issuer: " + parameters.getInput().getIssuer());
        getLog().info("[Generator] Subject: " + parameters.getInput().getSubject());
        getLog().info("[Generator] Years: " + parameters.getInput().getYears());
    }

    private void printOutputInformation() {
        getLog().info("[Generator] PubFile: " + parameters.getOutput().getPubFilename());
        getLog().info("[Generator] KeyFile: " + parameters.getOutput().getKeyFilename());
        getLog().info("[Generator] CertFile: " + parameters.getOutput().getCertFilename());
        getLog().info("[Generator] DirectoryName: " + parameters.getOutput().getDirectoryName());
        getLog().info("[Generator] OutputDirectory: " + parameters.getOutput().getOutputDirectory());
    }

    private void generate() throws MojoExecutionException {
        makeKeys();
        makeCustomDirectory();
        makeFiles();
        makeCustomResource();
    }

    private void makeKeys() {
        keysResponse = keysGenerator.execute(parameters);
    }

    private void makeCustomResource() throws MojoExecutionException {
        final String path = parameters.getOutput().getOutputDirectory();
        directoryBuilder.execute(path);
        customResource.execute(mavenProject, path);
    }

    private void makeCustomDirectory() throws MojoExecutionException {
        final String customDirectory = parameters.getOutput().getOutputDirectory() + File.separator + parameters.getOutput().getDirectoryName() + File.separator;
        directoryBuilder.execute(customDirectory);
    }

    private void makeFiles() {
        filesGenerator.execute(parameters, keysResponse);
    }

    /**
     * Setter maven project only for test.
     *
     * @param pproject the project to set
     */
    public void setProject(final MavenProject pproject) {
        this.mavenProject = pproject;
    }

    /**
     * Setter parameters only for test.
     *
     * @param pparameters the parameters of the project to set
     */
    public void setParameters(final Parameters pparameters) {
        this.parameters = pparameters;
    }

}
