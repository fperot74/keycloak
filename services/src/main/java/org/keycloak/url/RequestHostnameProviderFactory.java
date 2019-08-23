package org.keycloak.url;

import org.keycloak.models.KeycloakSession;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.HostnameProviderFactory;

public class RequestHostnameProviderFactory implements HostnameProviderFactory {

    @Override
    public HostnameProvider create(KeycloakSession session) {
        return new RequestHostnameProvider();
    }

    @Override
    public String getId() {
        return "request";
    }

}
