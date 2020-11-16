package com.github.yadickson.autocert;

import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.github.yadickson.autocert.directory.DirectoryBuilder;
import com.github.yadickson.autocert.directory.DirectoryBuilderException;
import com.github.yadickson.autocert.key.KeysGenerator;
import com.github.yadickson.autocert.key.KeysGeneratorException;
import com.github.yadickson.autocert.key.KeysResponse;
import com.github.yadickson.autocert.parameters.InputInformation;
import com.github.yadickson.autocert.parameters.OutputInformation;
import com.github.yadickson.autocert.parameters.Parameters;
import com.github.yadickson.autocert.writer.FilesGenerator;
import com.github.yadickson.autocert.writer.FilesGeneratorException;

@RunWith(MockitoJUnitRunner.class)
public class GeneratorPluginTest {

    private GeneratorPlugin generatorPlugin;

    @Mock
    private MavenProject projectMock;

    @Mock
    private Log logMock;

    @Mock
    private DirectoryBuilder directoryBuilderMock;

    @Mock
    private CustomResource customResourceMock;

    @Mock
    private KeysGenerator keysGeneratorMock;

    @Mock
    private FilesGenerator filesGeneratorMock;

    @Mock
    private KeysResponse keysResponseMock;

    @Mock
    private InputInformation inputInformation;

    @Mock
    private OutputInformation outputInformation;

    private Parameters parametersMock;

    private static final String PUBLIC_KEY_FILENAME = "public-key-filename";
    private static final String PRIVATE_KEY_FILENAME = "private-key-filename";
    private static final String CERTIFICATE_FILENAME = "certificate-filename";

    private static final String ALGORITHM = "algorithm";
    private static final Integer KEY_SIZE = 1024;

    private static final String SIGNATURE = "signature";
    private static final Integer YEARS = 4;
    private static final String ISSUER = "issuer";
    private static final String SUBJECT = "subject";

    private static final String DIRECTORY_NAME = "directory-name";
    private static final String OUTPUT_DIRECTORY = "output-directory";

    @Before
    public void setUp() {
        generatorPlugin = new GeneratorPlugin(
                keysGeneratorMock,
                filesGeneratorMock,
                directoryBuilderMock,
                customResourceMock
        );

        parametersMock = new Parameters(inputInformation, outputInformation);

        Mockito.when(inputInformation.getAlgorithm()).thenReturn(ALGORITHM);
        Mockito.when(inputInformation.getKeySize()).thenReturn(KEY_SIZE);
        Mockito.when(inputInformation.getSignature()).thenReturn(SIGNATURE);
        Mockito.when(inputInformation.getYears()).thenReturn(YEARS);
        Mockito.when(inputInformation.getIssuer()).thenReturn(ISSUER);
        Mockito.when(inputInformation.getSubject()).thenReturn(SUBJECT);

        Mockito.when(outputInformation.getPubFilename()).thenReturn(PUBLIC_KEY_FILENAME);
        Mockito.when(outputInformation.getKeyFilename()).thenReturn(PRIVATE_KEY_FILENAME);
        Mockito.when(outputInformation.getCertFilename()).thenReturn(CERTIFICATE_FILENAME);
        Mockito.when(outputInformation.getDirectoryName()).thenReturn(DIRECTORY_NAME);
        Mockito.when(outputInformation.getOutputDirectory()).thenReturn(OUTPUT_DIRECTORY);

        generatorPlugin.setLog(logMock);
        generatorPlugin.setProject(projectMock);
        generatorPlugin.setParameters(parametersMock);
    }

    @Test
    public void test_logger_messages() throws MojoExecutionException {

        generatorPlugin.execute();

        Mockito.verify(logMock).info(Mockito.eq("[Generator] PubFile: " + PUBLIC_KEY_FILENAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] KeyFile: " + PRIVATE_KEY_FILENAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] CertFile: " + CERTIFICATE_FILENAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Algorithm: " + ALGORITHM));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Signature: " + SIGNATURE));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] KeySize: " + KEY_SIZE));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Issuer: " + ISSUER));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Subject: " + SUBJECT));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] Years: " + YEARS));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] DirectoryName: " + DIRECTORY_NAME));
        Mockito.verify(logMock).info(Mockito.eq("[Generator] OutputDirectory: " + OUTPUT_DIRECTORY));
    }

    @Test
    public void it_should_check_all_process() throws Exception {

        Mockito.when(keysGeneratorMock.execute(Mockito.same(parametersMock))).thenReturn(keysResponseMock);

        generatorPlugin.execute();

        InOrder inOrder = Mockito.inOrder(keysGeneratorMock, directoryBuilderMock, filesGeneratorMock, customResourceMock);

        inOrder.verify(keysGeneratorMock).execute(Mockito.same(parametersMock));
        inOrder.verify(directoryBuilderMock).execute(Mockito.anyString());
        inOrder.verify(filesGeneratorMock).execute(Mockito.same(parametersMock), Mockito.same(keysResponseMock));
        inOrder.verify(customResourceMock).execute(Mockito.same(projectMock), Mockito.anyString());
    }

    @Test(expected = MojoExecutionException.class)
    public void it_should_throw_error_when_keys_generator_exception() throws Exception {
        Mockito.when(keysGeneratorMock.execute(Mockito.same(parametersMock))).thenThrow(KeysGeneratorException.class);
        generatorPlugin.execute();
    }

    @Test(expected = MojoExecutionException.class)
    public void it_should_throw_error_when_directory_builder_excetion_exception() throws Exception {
        Mockito.doThrow(DirectoryBuilderException.class).when(directoryBuilderMock).execute(Mockito.anyString());
        generatorPlugin.execute();
    }

    @Test(expected = MojoExecutionException.class)
    public void it_should_throw_error_when_files_generator_excetion_exception() throws Exception {
        Mockito.doThrow(FilesGeneratorException.class).when(filesGeneratorMock).execute(Mockito.same(parametersMock), Mockito.any(KeysResponse.class));
        generatorPlugin.execute();
    }
}
