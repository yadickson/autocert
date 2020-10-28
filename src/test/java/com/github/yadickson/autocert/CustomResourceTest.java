package com.github.yadickson.autocert;

import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"jdk.internal.reflect.*"})
public class CustomResourceTest {

    @Mock
    private Resource resourceMock;

    @Mock
    private MavenProject projectMock;

    @Test
    @PrepareForTest({CustomResource.class})
    public void it_should_set_resource_path_into_the_maven_project() throws Exception {

        final String filepath = "filepath";

        PowerMockito.whenNew(Resource.class).withNoArguments().thenReturn(resourceMock);

        CustomResource instance = new CustomResource();
        instance.execute(projectMock, filepath);

        InOrder inOrder = Mockito.inOrder(resourceMock, projectMock);

        inOrder.verify(resourceMock).setDirectory(Mockito.eq(filepath));
        inOrder.verify(projectMock).addResource(Mockito.same(resourceMock));
    }

}
