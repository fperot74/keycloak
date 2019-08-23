/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.theme;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class FolderThemeProvider implements ThemeProvider {

    private File themesDir;

    public FolderThemeProvider(File themesDir) {
        this.themesDir = themesDir;
    }

    @Override
    public int getProviderPriority() {
        return 100;
    }

    @Override
    public Theme getTheme(String name, Theme.Type type) throws IOException {
        if (themesDir == null) {
            return null;
        }

        File themeDir = getThemeDir(name, type);
        return themeDir.isDirectory() ? new FolderTheme(themeDir, name, type) : null;
    }

    @Override
    public Set<String> nameSet(Theme.Type type) {
        if (themesDir == null) {
            return Collections.emptySet();
        }

        final String typeName = type.name().toLowerCase();
        File[] themeDirs = themesDir.listFiles(pathname -> pathname.isDirectory() && new File(pathname, typeName).isDirectory());
        if (themeDirs != null) {
            return Arrays.stream(themeDirs).map(File::getName).collect(Collectors.toSet());
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public boolean hasTheme(String name, Theme.Type type) {
        return themesDir != null && getThemeDir(name, type).isDirectory();
    }

    @Override
    public void close() {
    }

    private File getThemeDir(String name, Theme.Type type) {
        return new File(themesDir, name + File.separator + type.name().toLowerCase());
    }

}
