/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.spec.EncodedKeySpec;
import java.util.Optional;

import javax.inject.Inject;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import com.github.yadickson.autocert.algorithm.AlgorithmMapper;
import com.github.yadickson.autocert.directory.DirectoryBuilder;
import com.github.yadickson.autocert.initializer.KeyPairInitialize;
import com.github.yadickson.autocert.initializer.KeyPairInitializeFactory;
import com.github.yadickson.autocert.key.certificate.CertificateGenerator;
import com.github.yadickson.autocert.key.keypair.KeyPairGenerator;
import com.github.yadickson.autocert.key.privatekey.PrivateKeyGenerator;
import com.github.yadickson.autocert.key.publickey.PublicKeyGenerator;
import com.github.yadickson.autocert.model.Algorithm;
import com.github.yadickson.autocert.model.Parameters;
import com.github.yadickson.autocert.model.Provider;
import com.github.yadickson.autocert.provider.ProviderConfiguration;
import com.github.yadickson.autocert.provider.ProviderDecorator;
import com.github.yadickson.autocert.writer.certificate.CertificateWriter;
import com.github.yadickson.autocert.writer.privatekey.PrivateKeyWriter;
import com.github.yadickson.autocert.writer.publickey.PublicKeyWriter;

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
    private String algorithmConfig;

    /**
     * Algorithm.
     */
    @Parameter(
            property = "autocert.keySize",
            alias = "keySize",
            required = false,
            defaultValue = "1024")
    private Integer keySizeConfig;

    /**
     * Signature.
     */
    @Parameter(
            property = "autocert.signature",
            alias = "signature",
            required = false,
            defaultValue = "SHA256withRSA")
    private String signatureConfig;

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
    private File outputDirectory;

    /**
     * Parameters configuration plugin.
     */
    private Parameters parameters;

    /**
     * Custom directory.
     */
    private String customDirectory;

    /**
     * Algorithm.
     */
    private Algorithm algorithm;

    /**
     * Algorithm initialize.
     */
    private KeyPairInitialize initializer;

    /**
     * Key pair generate.
     */
    private KeyPair keyPair;

    /**
     * Private key generate.
     */
    private EncodedKeySpec privateKey;

    /**
     * Public key generate.
     */
    private EncodedKeySpec publicKey;

    /**
     * Certificate generate.
     */
    private Certificate certificate;

    /**
     * Security provider configuration.
     */
    private final ProviderConfiguration providerConfiguration;

    /**
     * Directory builder.
     */
    private final DirectoryBuilder directoryBuilder;

    /**
     * Maven custom resource.
     */
    private final CustomResource customResource;

    /**
     * Algorithm mapper.
     */
    private final AlgorithmMapper algorithmMapper;

    /**
     * Initialize factory.
     */
    private final KeyPairInitializeFactory initializerFactory;

    /**
     * KeyPair generator.
     */
    private final KeyPairGenerator keyPairGenerator;

    /**
     * Private key generator.
     */
    private final PrivateKeyGenerator privateKeyGenerator;

    /**
     * Public key generator.
     */
    private final PublicKeyGenerator publicKeyGenerator;

    /**
     * Certificate generator.
     */
    private final CertificateGenerator certificateGenerator;

    /**
     * Private key writer.
     */
    private final PrivateKeyWriter privateKeyWriter;

    /**
     * Public key writer.
     */
    private final PublicKeyWriter publicKeyWriter;

    /**
     * Certificate writer.
     */
    private final CertificateWriter certificateWriter;

    @Inject
    public GeneratorPlugin(
            final ProviderConfiguration providerConfiguration,
            final DirectoryBuilder directoryBuilder,
            final CustomResource customResource,
            final AlgorithmMapper algorithmMapper,
            final KeyPairInitializeFactory initializerFactory,
            final KeyPairGenerator keyPairGenerator,
            final PrivateKeyGenerator privateKeyGenerator,
            final PublicKeyGenerator publicKeyGenerator,
            final CertificateGenerator certificateGenerator,
            final PrivateKeyWriter privateKeyWriter,
            final PublicKeyWriter publicKeyWriter,
            final CertificateWriter certificateWriter
    ) {
        this.providerConfiguration = providerConfiguration;
        this.directoryBuilder = directoryBuilder;
        this.customResource = customResource;
        this.algorithmMapper = algorithmMapper;
        this.initializerFactory = initializerFactory;
        this.keyPairGenerator = keyPairGenerator;
        this.privateKeyGenerator = privateKeyGenerator;
        this.publicKeyGenerator = publicKeyGenerator;
        this.certificateGenerator = certificateGenerator;
        this.privateKeyWriter = privateKeyWriter;
        this.publicKeyWriter = publicKeyWriter;
        this.certificateWriter = certificateWriter;
    }

    /**
     * Maven execute method.
     *
     * @throws MojoExecutionException Launch if the generation process throws an
     * error
     */
    @Override
    public void execute() throws MojoExecutionException {

        try (ProviderDecorator provider = new ProviderDecorator(providerConfiguration)) {

            makeParameters();
            printParameters();

            findAlgorithm();
            findAlgorithmInitializer();

            makeKeyPair(provider);
            makePrivateKey();
            makePublicKey();
            makeCertificate(provider);

            makeCustomResource();
            makeCustomDirectory();

            writePrivateKeyFile();
            writePublicKeyFile();
            writeCertificateFile();

        } catch (IOException | RuntimeException ex) {
            getLog().error(ex.getMessage(), ex);
            throw new MojoExecutionException("Execute error", ex);
        }
    }

    private void makeParameters() {
        parameters = Optional.ofNullable(parameters).orElse(new Parameters(pubFilename, keyFilename, certFilename, algorithmConfig, keySizeConfig, signatureConfig, years, issuer, subject, directoryName, outputDirectory));
    }

    private void printParameters() {
        getLog().info("[Generator] PubFile: " + parameters.getPubFilename());
        getLog().info("[Generator] KeyFile: " + parameters.getKeyFilename());
        getLog().info("[Generator] CertFile: " + parameters.getCertFilename());
        getLog().info("[Generator] Algorithm: " + parameters.getAlgorithm());
        getLog().info("[Generator] Signature: " + parameters.getSignature());
        getLog().info("[Generator] KeySize: " + parameters.getKeySize());
        getLog().info("[Generator] Issuer: " + parameters.getIssuer());
        getLog().info("[Generator] Subject: " + parameters.getSubject());
        getLog().info("[Generator] Years: " + parameters.getYears());
        getLog().info("[Generator] DirectoryName: " + parameters.getDirectoryName());
        getLog().info("[Generator] OutputDirectory: " + parameters.getOutputDirectory().getPath());
    }

    private void findAlgorithm() {
        algorithm = algorithmMapper.apply(parameters.getAlgorithm());
    }

    private void findAlgorithmInitializer() {
        initializer = initializerFactory.apply(algorithm);
    }

    private void makeKeyPair(Provider provider) {
        keyPair = keyPairGenerator.execute(provider, initializer, algorithm, parameters.getKeySize());
    }

    private void makePrivateKey() {
        privateKey = privateKeyGenerator.execute(keyPair);
    }

    private void makePublicKey() {
        publicKey = publicKeyGenerator.execute(keyPair);
    }

    private void makeCertificate(Provider provider) {
        certificate = certificateGenerator.execute(provider, keyPair, parameters);
    }

    private void makeCustomResource() throws MojoExecutionException {
        final String path = parameters.getOutputDirectory().getPath();
        directoryBuilder.execute(path);
        customResource.execute(mavenProject, path);
    }

    private void makeCustomDirectory() throws MojoExecutionException {
        customDirectory = parameters.getOutputDirectory().getPath() + File.separator + parameters.getDirectoryName() + File.separator;
        directoryBuilder.execute(customDirectory);
    }

    private void writePrivateKeyFile() {
        String keyFilePath = customDirectory + parameters.getKeyFilename();
        privateKeyWriter.execute(keyFilePath, privateKey);
    }

    private void writePublicKeyFile() {
        String pubFilePath = customDirectory + parameters.getPubFilename();
        publicKeyWriter.execute(pubFilePath, publicKey);
    }

    private void writeCertificateFile() {
        String certFilePath = customDirectory + parameters.getCertFilename();
        certificateWriter.execute(certFilePath, certificate);
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
