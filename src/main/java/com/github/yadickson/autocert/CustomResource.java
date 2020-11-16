/*
 * Copyright (C) 2020 Yadickson Soto
 *
 * See <http://www.gnu.org/licenses/gpl-3.0.html>.
 */
package com.github.yadickson.autocert;

import javax.inject.Named;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;

/**
 *
 * @author Yadickson Soto
 */
@Named
public class CustomResource {

    public void execute(final MavenProject mavenProject, final String path) {
        Resource resource = new Resource();
        resource.setDirectory(path);
        mavenProject.addResource(resource);
    }
}
