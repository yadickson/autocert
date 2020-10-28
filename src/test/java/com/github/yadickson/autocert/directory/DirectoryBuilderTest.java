package com.github.yadickson.autocert.directory;

import java.io.File;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"jdk.internal.reflect.*"})
public class DirectoryBuilderTest {

    @Mock
    private File fileMock;

    @Test
    @PrepareForTest({DirectoryBuilder.class})
    public void it_should_not_make_directory() throws Exception {
        final String filename = "filename";

        PowerMockito.whenNew(File.class).withArguments(filename).thenReturn(fileMock);

        Mockito.when(fileMock.exists()).thenReturn(Boolean.TRUE);

        DirectoryBuilder instance = new DirectoryBuilder();
        instance.execute(filename);

        Mockito.verify(fileMock).exists();
        Mockito.verify(fileMock, Mockito.never()).mkdirs();
    }

    @Test
    @PrepareForTest({DirectoryBuilder.class})
    public void it_should_make_directory_if_does_not_exists() throws Exception {
        final String filename = "filename";

        PowerMockito.whenNew(File.class).withArguments(filename).thenReturn(fileMock);

        Mockito.when(fileMock.exists()).thenReturn(Boolean.FALSE);
        Mockito.when(fileMock.mkdirs()).thenReturn(Boolean.TRUE);

        DirectoryBuilder instance = new DirectoryBuilder();
        instance.execute(filename);

        Mockito.verify(fileMock).exists();
        Mockito.verify(fileMock).mkdirs();
    }

    @Test(expected = DirectoryBuilderException.class)
    @PrepareForTest({DirectoryBuilder.class})
    public void it_should_throw_error_when_does_not_possible_to_make_a_directory() throws Exception {
        final String filename = "filename";

        PowerMockito.whenNew(File.class).withArguments(filename).thenReturn(fileMock);

        Mockito.when(fileMock.exists()).thenReturn(Boolean.FALSE);
        Mockito.when(fileMock.mkdirs()).thenReturn(Boolean.FALSE);

        DirectoryBuilder instance = new DirectoryBuilder();
        instance.execute(filename);
    }

}
