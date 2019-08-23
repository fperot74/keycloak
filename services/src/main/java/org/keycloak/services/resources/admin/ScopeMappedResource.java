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

package org.keycloak.services.resources.admin;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.ScopeContainerModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Base class for managing the scope mappings of a specific client.
 *
 * @resource Scope Mappings
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class ScopeMappedResource {
    protected RealmModel realm;
    protected AdminPermissionEvaluator auth;
    protected AdminPermissionEvaluator.RequirePermissionCheck managePermission;
    protected AdminPermissionEvaluator.RequirePermissionCheck viewPermission;

    protected ScopeContainerModel scopeContainer;
    protected KeycloakSession session;
    protected AdminEventBuilder adminEvent;

    public ScopeMappedResource(RealmModel realm, AdminPermissionEvaluator auth, ScopeContainerModel scopeContainer,
                               KeycloakSession session, AdminEventBuilder adminEvent,
                               AdminPermissionEvaluator.RequirePermissionCheck managePermission,
                               AdminPermissionEvaluator.RequirePermissionCheck viewPermission) {
        this.realm = realm;
        this.auth = auth;
        this.scopeContainer = scopeContainer;
        this.session = session;
        this.adminEvent = adminEvent.resource(ResourceType.REALM_SCOPE_MAPPING);
        this.managePermission = managePermission;
        this.viewPermission = viewPermission;
    }

    /**
     * Get all scope mappings for the client
     *
     * @return
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public MappingsRepresentation getScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        MappingsRepresentation all = new MappingsRepresentation();
        Set<RoleModel> realmMappings = scopeContainer.getRealmScopeMappings();
        if (!realmMappings.isEmpty()) {
            List<RoleRepresentation> realmRep = realmMappings.stream().map(ModelToRepresentation::toBriefRepresentation).collect(Collectors.toList());
            all.setRealmMappings(realmRep);
        }

        List<ClientModel> clients = realm.getClients();
        if (!clients.isEmpty()) {
            Map<String, ClientMappingsRepresentation> clientMappings = new HashMap<>();
            for (ClientModel client : clients) {
                Set<RoleModel> roleMappings = KeycloakModelUtils.getClientScopeMappings(client, this.scopeContainer); //client.getClientScopeMappings(this.client);
                if (!roleMappings.isEmpty()) {
                    ClientMappingsRepresentation mappings = new ClientMappingsRepresentation();
                    mappings.setId(client.getId());
                    mappings.setClient(client.getClientId());
                    List<RoleRepresentation> roles = roleMappings.stream().map(ModelToRepresentation::toBriefRepresentation).collect(Collectors.toList());
                    mappings.setMappings(roles);
                    clientMappings.put(client.getClientId(), mappings);
                    all.setClientMappings(clientMappings);
                }
            }
        }
        return all;
    }

    /**
     * Get realm-level roles associated with the client's scope
     *
     * @return
     */
    @Path("realm")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getRealmScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        Set<RoleModel> realmMappings = scopeContainer.getRealmScopeMappings();
        return realmMappings.stream().map(ModelToRepresentation::toBriefRepresentation).collect(Collectors.toList());
    }

    /**
     * Get realm-level roles that are available to attach to this client's scope
     *
     * @return
     */
    @Path("realm/available")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getAvailableRealmScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        Set<RoleModel> roles = realm.getRoles();
        return getAvailable(auth, scopeContainer, roles);
    }

    public static List<RoleRepresentation> getAvailable(AdminPermissionEvaluator auth, ScopeContainerModel client, Set<RoleModel> roles) {
        return roles.stream().filter(r -> !client.hasScope(r) && auth.roles().canMapClientScope(r))
            .map(ModelToRepresentation::toBriefRepresentation).collect(Collectors.toList());
    }

    /**
     * Get effective realm-level roles associated with the client's scope
     *
     * What this does is recurse
     * any composite roles associated with the client's scope and adds the roles to this lists.  The method is really
     * to show a comprehensive total view of realm-level roles associated with the client.
     *
     * @return
     */
    @Path("realm/composite")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public List<RoleRepresentation> getCompositeRealmScopeMappings() {
        viewPermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        Set<RoleModel> roles = realm.getRoles();
        return getComposite(scopeContainer, roles);
    }

    public static List<RoleRepresentation> getComposite(ScopeContainerModel client, Set<RoleModel> roles) {
        return roles.stream().filter(client::hasScope).map(ModelToRepresentation::toBriefRepresentation).collect(Collectors.toList());
    }

    /**
     * Add a set of realm-level roles to the client's scope
     *
     * @param roles
     */
    @Path("realm")
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void addRealmScopeMappings(List<RoleRepresentation> roles) {
        managePermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        for (RoleRepresentation role : roles) {
            RoleModel roleModel = realm.getRoleById(role.getId());
            if (roleModel == null) {
                throw new NotFoundException("Role not found");
            }
            scopeContainer.addScopeMapping(roleModel);
        }

        adminEvent.operation(OperationType.CREATE).resourcePath(session.getContext().getUri()).representation(roles).success();
    }

    /**
     * Remove a set of realm-level roles from the client's scope
     *
     * @param roles
     */
    @Path("realm")
    @DELETE
    @Consumes(MediaType.APPLICATION_JSON)
    public void deleteRealmScopeMappings(List<RoleRepresentation> roles) {
        managePermission.require();

        if (scopeContainer == null) {
            throw new NotFoundException("Could not find client");
        }

        if (roles == null) {
            Set<RoleModel> roleModels = scopeContainer.getRealmScopeMappings();
            roles = new LinkedList<>();

            for (RoleModel roleModel : roleModels) {
                scopeContainer.deleteScopeMapping(roleModel);
                roles.add(ModelToRepresentation.toBriefRepresentation(roleModel));
            }

       } else {
            for (RoleRepresentation role : roles) {
                RoleModel roleModel = realm.getRoleById(role.getId());
                if (roleModel == null) {
                    throw new NotFoundException("Client not found");
                }
                scopeContainer.deleteScopeMapping(roleModel);
            }
        }

        adminEvent.operation(OperationType.DELETE).resourcePath(session.getContext().getUri()).representation(roles).success();

    }

    @Path("clients/{client}")
    public ScopeMappedClientResource getClientByIdScopeMappings(@PathParam("client") String client) {
        ClientModel clientModel = realm.getClientById(client);
        if (clientModel == null) {
            throw new NotFoundException("Could not find client");
        }
        return new ScopeMappedClientResource(realm, auth, this.scopeContainer, session, clientModel, adminEvent, managePermission, viewPermission);
    }
}
