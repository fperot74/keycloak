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

package org.keycloak.exportimport.util;

import static org.keycloak.models.utils.ModelToRepresentation.toRepresentation;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.AuthorizationProviderFactory;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.common.Version;
import org.keycloak.common.util.Base64;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserConsentModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ComponentExportRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.RolesRepresentation;
import org.keycloak.representations.idm.ScopeMappingRepresentation;
import org.keycloak.representations.idm.UserConsentRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceOwnerRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.core.JsonEncoding;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ExportUtils {

    public static RealmRepresentation exportRealm(KeycloakSession session, RealmModel realm, boolean includeUsers, boolean internal) {
        ExportOptions opts = new ExportOptions(false, true, true);
        if (includeUsers) {
            opts.setUsersIncluded(true);
        }
        return exportRealm(session, realm, opts, internal);
    }

    private static <T,R> List<R> mapList(Collection<T> source, Function<T, R> mapper) {
        return source.stream().map(mapper).collect(Collectors.toList());
    }

    private static <T,R> LinkedList<R> mapLinkedList(Collection<T> source, Function<T, R> mapper) {
        LinkedList<R> res = new LinkedList<>();
        res.addAll(source.stream().map(mapper).collect(Collectors.toList()));
        return res;
    }

    private static <T> void whenNotEmpty(List<T> list, Consumer<List<T>> consumer) {
        if (!list.isEmpty()) {
            consumer.accept(list);
        }
    }

    public static RealmRepresentation exportRealm(KeycloakSession session, RealmModel realm, ExportOptions options, boolean internal) {
        RealmRepresentation rep = ModelToRepresentation.toRepresentation(realm, internal);
        ModelToRepresentation.exportAuthenticationFlows(realm, rep);
        ModelToRepresentation.exportRequiredActions(realm, rep);

        // Project/product version
        rep.setKeycloakVersion(Version.VERSION);

        // Client Scopes
        List<ClientScopeModel> clientScopeModels = realm.getClientScopes();
        List<ClientScopeRepresentation> clientScopesReps = mapList(clientScopeModels, ModelToRepresentation::toRepresentation);
        rep.setClientScopes(clientScopesReps);

        List<String> defaultClientScopeNames = mapList(realm.getDefaultClientScopes(true), ClientScopeModel::getName);
        rep.setDefaultDefaultClientScopes(defaultClientScopeNames);

        List<String> optionalClientScopeNames = mapList(realm.getDefaultClientScopes(false), ClientScopeModel::getName);
        rep.setDefaultOptionalClientScopes(optionalClientScopeNames);

        // Clients
        List<ClientModel> clients = Collections.emptyList();

        if (options.isClientsIncluded()) {
            clients = realm.getClients();
            List<ClientRepresentation> clientReps = mapList(clients, app -> exportClient(session, app));
            rep.setClients(clientReps);
        }

        // Groups and Roles
        if (options.isGroupsAndRolesIncluded()) {
            ModelToRepresentation.exportGroups(realm, rep);

            List<RoleRepresentation> realmRoleReps = null;

            Set<RoleModel> realmRoles = realm.getRoles();
            if (realmRoles != null && !realmRoles.isEmpty()) {
                realmRoleReps = exportRoles(realmRoles);
            }

            RolesRepresentation rolesRep = new RolesRepresentation();
            if (realmRoleReps != null) {
                rolesRep.setRealm(realmRoleReps);
            }

            if (options.isClientsIncluded()) {
                Map<String, List<RoleRepresentation>> clientRolesReps = clients.stream().collect(Collectors.toMap(ClientModel::getId, c -> exportRoles(c.getRoles())));
                if (!clientRolesReps.isEmpty()) {
                    rolesRep.setClient(clientRolesReps);
                }
            }
            rep.setRoles(rolesRep);
        }

        // Scopes
        Map<String, List<ScopeMappingRepresentation>> clientScopeReps = new HashMap<>();

        if (options.isClientsIncluded()) {
            List<ClientModel> allClients = new ArrayList<>(clients);

            // Scopes of clients
            for (ClientModel client : allClients) {
                Set<RoleModel> clientScopes = client.getScopeMappings();
                ScopeMappingRepresentation scopeMappingRep = null;
                for (RoleModel scope : clientScopes) {
                    if (scope.getContainer() instanceof RealmModel) {
                        if (scopeMappingRep == null) {
                            scopeMappingRep = rep.clientScopeMapping(client.getClientId());
                        }
                        scopeMappingRep.role(scope.getName());
                    } else {
                        ClientModel app = (ClientModel) scope.getContainer();
                        String appName = app.getClientId();
                        List<ScopeMappingRepresentation> currentAppScopes = clientScopeReps.computeIfAbsent(appName, k -> new ArrayList<>());

                        ScopeMappingRepresentation currentClientScope = currentAppScopes.stream()
                            .filter(s -> client.getClientId().equals(s.getClient()))
                            .findAny().orElseGet(() -> {
                                ScopeMappingRepresentation newScope = new ScopeMappingRepresentation();
                                newScope.setClient(client.getClientId());
                                currentAppScopes.add(newScope);
                                return newScope;
                            });
                        currentClientScope.role(scope.getName());
                    }
                }
            }
        }

        // Scopes of client scopes
        for (ClientScopeModel clientScope : realm.getClientScopes()) {
            Set<RoleModel> clientScopes = clientScope.getScopeMappings();
            ScopeMappingRepresentation scopeMappingRep = null;
            for (RoleModel scope : clientScopes) {
                if (scope.getContainer() instanceof RealmModel) {
                    if (scopeMappingRep == null) {
                        scopeMappingRep = rep.clientScopeScopeMapping(clientScope.getName());
                    }
                    scopeMappingRep.role(scope.getName());
                } else {
                    ClientModel app = (ClientModel)scope.getContainer();
                    String appName = app.getClientId();
                    List<ScopeMappingRepresentation> currentAppScopes = clientScopeReps.computeIfAbsent(appName, k -> new ArrayList<>());

                    ScopeMappingRepresentation currentClientTemplateScope = currentAppScopes.stream()
                        .filter(s -> clientScope.getName().equals(s.getClientScope()))
                        .findAny().orElseGet(() -> {
                            ScopeMappingRepresentation newScope = new ScopeMappingRepresentation();
                            newScope.setClientScope(clientScope.getName());
                            currentAppScopes.add(newScope);
                            return newScope;
                    });
                    currentClientTemplateScope.role(scope.getName());
                }
            }
        }

        if (!clientScopeReps.isEmpty()) {
            rep.setClientScopeMappings(clientScopeReps);
        }

        // Finally users if needed
        if (options.isUsersIncluded()) {
            List<UserModel> allUsers = session.users().getUsers(realm, true);
            List<UserRepresentation> users = mapLinkedList(allUsers, u -> exportUser(session, realm, u, options));
            whenNotEmpty(users, rep::setUsers);

            List<UserRepresentation> federatedUsers = new LinkedList<>();
            federatedUsers.addAll(session.userFederatedStorage().getStoredUsers(realm, 0, -1).stream()
                .map(uid -> exportFederatedUser(session, realm, uid, options)).collect(Collectors.toList()));
            whenNotEmpty(federatedUsers, rep::setFederatedUsers);
        }

        // components
        MultivaluedHashMap<String, ComponentExportRepresentation> components = exportComponents(realm, realm.getId());
        rep.setComponents(components);

        return rep;
    }

    public static MultivaluedHashMap<String, ComponentExportRepresentation> exportComponents(RealmModel realm, String parentId) {
        List<ComponentModel> componentList = realm.getComponents(parentId);
        MultivaluedHashMap<String, ComponentExportRepresentation> components = new MultivaluedHashMap<>();
        for (ComponentModel component : componentList) {
            ComponentExportRepresentation compRep = new ComponentExportRepresentation();
            compRep.setId(component.getId());
            compRep.setProviderId(component.getProviderId());
            compRep.setConfig(component.getConfig());
            compRep.setName(component.getName());
            compRep.setSubType(component.getSubType());
            compRep.setSubComponents(exportComponents(realm, component.getId()));
            components.add(component.getProviderType(), compRep);
        }
        return components;
    }

    /**
     * Full export of application including claims and secret
     * @param client
     * @return full ApplicationRepresentation
     */
    public static ClientRepresentation exportClient(KeycloakSession session, ClientModel client) {
        ClientRepresentation clientRep = ModelToRepresentation.toRepresentation(client, session);
        clientRep.setSecret(client.getSecret());
        clientRep.setAuthorizationSettings(exportAuthorizationSettings(session,client));
        return clientRep;
    }

    public static ResourceServerRepresentation exportAuthorizationSettings(KeycloakSession session, ClientModel client) {
        AuthorizationProviderFactory providerFactory = (AuthorizationProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(AuthorizationProvider.class);
        AuthorizationProvider authorization = providerFactory.create(session, client.getRealm());
        StoreFactory storeFactory = authorization.getStoreFactory();
        ResourceServer settingsModel = authorization.getStoreFactory().getResourceServerStore().findById(client.getId());

        if (settingsModel == null) {
            return null;
        }

        ResourceServerRepresentation representation = toRepresentation(settingsModel, client);

        representation.setId(null);
        representation.setName(null);
        representation.setClientId(null);

        List<ResourceRepresentation> resources = storeFactory.getResourceStore().findByResourceServer(settingsModel.getId())
                .stream().map(resource -> {
                    ResourceRepresentation rep = toRepresentation(resource, settingsModel, authorization);

                    if (rep.getOwner().getId().equals(settingsModel.getId())) {
                        rep.setOwner((ResourceOwnerRepresentation) null);
                    } else {
                        rep.getOwner().setId(null);
                    }
                    rep.getScopes().forEach(scopeRepresentation -> {
                        scopeRepresentation.setId(null);
                        scopeRepresentation.setIconUri(null);
                    });

                    return rep;
                }).collect(Collectors.toList());

        representation.setResources(resources);

        List<PolicyRepresentation> policies = new ArrayList<>();
        PolicyStore policyStore = storeFactory.getPolicyStore();

        policies.addAll(policyStore.findByResourceServer(settingsModel.getId())
                .stream().filter(policy -> !policy.getType().equals("resource") && !policy.getType().equals("scope") && policy.getOwner() == null)
                .map(policy -> createPolicyRepresentation(authorization, policy)).collect(Collectors.toList()));
        policies.addAll(policyStore.findByResourceServer(settingsModel.getId())
                .stream().filter(policy -> (policy.getType().equals("resource") || policy.getType().equals("scope") && policy.getOwner() == null))
                .map(policy -> createPolicyRepresentation(authorization, policy)).collect(Collectors.toList()));

        representation.setPolicies(policies);

        List<ScopeRepresentation> scopes = storeFactory.getScopeStore().findByResourceServer(settingsModel.getId()).stream().map(scope -> {
            ScopeRepresentation rep = toRepresentation(scope);

            rep.setPolicies(null);
            rep.setResources(null);

            return rep;
        }).collect(Collectors.toList());

        representation.setScopes(scopes);

        return representation;
    }

    private static PolicyRepresentation createPolicyRepresentation(AuthorizationProvider authorizationProvider, Policy policy) {
        try {
            PolicyRepresentation rep = toRepresentation(policy, authorizationProvider, true, true);

            Map<String, String> config = new HashMap<>(rep.getConfig());

            rep.setConfig(config);

            Set<Scope> scopes = policy.getScopes();
            if (!scopes.isEmpty()) {
                List<String> scopeNames = mapList(scopes, Scope::getName);
                config.put("scopes", JsonSerialization.writeValueAsString(scopeNames));
            }

            Set<Resource> policyResources = policy.getResources();

            if (!policyResources.isEmpty()) {
                List<String> resourceNames = mapList(policyResources, Resource::getName);
                config.put("resources", JsonSerialization.writeValueAsString(resourceNames));
            }

            Set<Policy> associatedPolicies = policy.getAssociatedPolicies();
            if (!associatedPolicies.isEmpty()) {
                config.put("applyPolicies", JsonSerialization.writeValueAsString(associatedPolicies.stream().map(Policy::getName).collect(Collectors.toList())));
            }

            return rep;
        } catch (Exception e) {
            throw new RuntimeException("Error while exporting policy [" + policy.getName() + "].", e);
        }
    }

    public static List<RoleRepresentation> exportRoles(Collection<RoleModel> roles) {
        return mapList(roles, ExportUtils::exportRole);
    }

    public static List<String> getRoleNames(Collection<RoleModel> roles) {
        return mapList(roles, RoleModel::getName);
    }

    /**
     * Full export of role including composite roles
     * @param role
     * @return RoleRepresentation with all stuff filled (including composite roles)
     */
    public static RoleRepresentation exportRole(RoleModel role) {
        RoleRepresentation roleRep = ModelToRepresentation.toRepresentation(role);

        Set<RoleModel> composites = role.getComposites();
        if (composites != null && !composites.isEmpty()) {
            Set<String> compositeRealmRoles = new HashSet<>();
            Map<String, List<String>> compositeClientRoles = new HashMap<>();

            for (RoleModel composite : composites) {
                RoleContainerModel crContainer = composite.getContainer();
                if (crContainer instanceof RealmModel) {
                    compositeRealmRoles.add(composite.getName());
                } else {
                    ClientModel app = (ClientModel)crContainer;
                    String appName = app.getClientId();
                    compositeClientRoles.computeIfAbsent(appName, k -> new ArrayList<>())
                        .add(composite.getName());
                }
            }

            RoleRepresentation.Composites compRep = new RoleRepresentation.Composites();
            if (!compositeRealmRoles.isEmpty()) {
                compRep.setRealm(compositeRealmRoles);
            }
            if (!compositeClientRoles.isEmpty()) {
                compRep.setClient(compositeClientRoles);
            }

            roleRep.setComposites(compRep);
        }

        return roleRep;
    }

    /**
     * Full export of user (including role mappings and credentials)
     *
     * @param user
     * @return fully exported user representation
     */
    public static UserRepresentation exportUser(KeycloakSession session, RealmModel realm, UserModel user, ExportOptions options) {
        UserRepresentation userRep = ModelToRepresentation.toRepresentation(session, realm, user);

        // Social links
        Set<FederatedIdentityModel> socialLinks = session.users().getFederatedIdentities(user, realm);
        List<FederatedIdentityRepresentation> socialLinkReps = mapList(socialLinks, ExportUtils::exportSocialLink);
        whenNotEmpty(socialLinkReps, userRep::setFederatedIdentities);

        // Role mappings
        Set<RoleModel> roles = user.getRoleMappings();
        List<String> realmRoleNames = new ArrayList<>();
        Map<String, List<String>> clientRoleNames = new HashMap<>();
        for (RoleModel role : roles) {
            if (role.getContainer() instanceof RealmModel) {
                realmRoleNames.add(role.getName());
            } else {
                ClientModel client = (ClientModel)role.getContainer();
                String clientId = client.getClientId();
                List<String> currentClientRoles = clientRoleNames.computeIfAbsent(clientId, k -> new ArrayList<>());
                currentClientRoles.add(role.getName());
            }
        }

        whenNotEmpty(realmRoleNames, userRep::setRealmRoles);
        if (!clientRoleNames.isEmpty()) {
            userRep.setClientRoles(clientRoleNames);
        }

        // Credentials
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentials(realm, user);
        List<CredentialRepresentation> credReps = mapList(creds, ExportUtils::exportCredential);
        userRep.setCredentials(credReps);
        userRep.setFederationLink(user.getFederationLink());

        // Grants
        List<UserConsentModel> consents = session.users().getConsents(realm, user.getId());
        LinkedList<UserConsentRepresentation> consentReps = mapLinkedList(consents, ModelToRepresentation::toRepresentation);
        whenNotEmpty(consentReps, userRep::setClientConsents);

        // Not Before
        int notBefore = session.users().getNotBeforeOfUser(realm, user);
        userRep.setNotBefore(notBefore);

        // Service account
        if (user.getServiceAccountClientLink() != null) {
            String clientInternalId = user.getServiceAccountClientLink();
            ClientModel client = realm.getClientById(clientInternalId);
            if (client != null) {
                userRep.setServiceAccountClientId(client.getClientId());
            }
        }

        if (options.isGroupsAndRolesIncluded()) {
            List<String> groups = mapLinkedList(user.getGroups(), ModelToRepresentation::buildGroupPath);
            userRep.setGroups(groups);
        }
        return userRep;
    }

    public static FederatedIdentityRepresentation exportSocialLink(FederatedIdentityModel socialLink) {
        FederatedIdentityRepresentation socialLinkRep = new FederatedIdentityRepresentation();
        socialLinkRep.setIdentityProvider(socialLink.getIdentityProvider());
        socialLinkRep.setUserId(socialLink.getUserId());
        socialLinkRep.setUserName(socialLink.getUserName());
        return socialLinkRep;
    }

    public static CredentialRepresentation exportCredential(CredentialModel userCred) {
        CredentialRepresentation credRep = new CredentialRepresentation();
        credRep.setType(userCred.getType());
        credRep.setDevice(userCred.getDevice());
        credRep.setHashedSaltedValue(userCred.getValue());
        if (userCred.getSalt() != null) credRep.setSalt(Base64.encodeBytes(userCred.getSalt()));
        credRep.setHashIterations(userCred.getHashIterations());
        credRep.setCounter(userCred.getCounter());
        credRep.setAlgorithm(userCred.getAlgorithm());
        credRep.setDigits(userCred.getDigits());
        credRep.setCreatedDate(userCred.getCreatedDate());
        credRep.setConfig(userCred.getConfig());
        credRep.setPeriod(userCred.getPeriod());
        return credRep;
    }

    // Streaming API

    public static void exportUsersToStream(KeycloakSession session, RealmModel realm, List<UserModel> usersToExport, ObjectMapper mapper, OutputStream os) throws IOException {
        exportUsersToStream(session, realm, usersToExport, mapper, os, new ExportOptions());
    }

    public static void exportUsersToStream(KeycloakSession session, RealmModel realm, List<UserModel> usersToExport, ObjectMapper mapper, OutputStream os, ExportOptions options) throws IOException {
        JsonFactory factory = mapper.getFactory();
        JsonGenerator generator = factory.createGenerator(os, JsonEncoding.UTF8);
        try {
            if (mapper.isEnabled(SerializationFeature.INDENT_OUTPUT)) {
                generator.useDefaultPrettyPrinter();
            }
            generator.writeStartObject();
            generator.writeStringField("realm", realm.getName());
            // generator.writeStringField("strategy", strategy.toString());
            generator.writeFieldName("users");
            generator.writeStartArray();

            for (UserModel user : usersToExport) {
                UserRepresentation userRep = ExportUtils.exportUser(session, realm, user, options);
                generator.writeObject(userRep);
            }

            generator.writeEndArray();
            generator.writeEndObject();
        } finally {
            generator.close();
        }
    }

    public static void exportFederatedUsersToStream(KeycloakSession session, RealmModel realm, List<String> usersToExport, ObjectMapper mapper, OutputStream os) throws IOException {
        exportFederatedUsersToStream(session, realm, usersToExport, mapper, os, new ExportOptions());
    }

    public static void exportFederatedUsersToStream(KeycloakSession session, RealmModel realm, List<String> usersToExport, ObjectMapper mapper, OutputStream os, ExportOptions options) throws IOException {
        JsonFactory factory = mapper.getFactory();
        JsonGenerator generator = factory.createGenerator(os, JsonEncoding.UTF8);
        try {
            if (mapper.isEnabled(SerializationFeature.INDENT_OUTPUT)) {
                generator.useDefaultPrettyPrinter();
            }
            generator.writeStartObject();
            generator.writeStringField("realm", realm.getName());
            // generator.writeStringField("strategy", strategy.toString());
            generator.writeFieldName("federatedUsers");
            generator.writeStartArray();

            for (String userId : usersToExport) {
                UserRepresentation userRep = ExportUtils.exportFederatedUser(session, realm, userId, options);
                generator.writeObject(userRep);
            }

            generator.writeEndArray();
            generator.writeEndObject();
        } finally {
            generator.close();
        }
    }

    /**
     * Full export of user data stored in federated storage (including role mappings and credentials)
     *
     * @param id
     * @return fully exported user representation
     */
    public static UserRepresentation exportFederatedUser(KeycloakSession session, RealmModel realm, String id, ExportOptions options) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setId(id);
        MultivaluedHashMap<String, String> attributes = session.userFederatedStorage().getAttributes(realm, id);
        if (!attributes.isEmpty()) {
            Map<String, List<String>> attrs = new HashMap<>();
            attrs.putAll(attributes);
            userRep.setAttributes(attrs);
        }

        Set<String> requiredActions = session.userFederatedStorage().getRequiredActions(realm, id);
        if (!requiredActions.isEmpty()) {
            List<String> actions = new LinkedList<>();
            actions.addAll(requiredActions);
            userRep.setRequiredActions(actions);
        }

        // Social links
        Set<FederatedIdentityModel> socialLinks = session.userFederatedStorage().getFederatedIdentities(id, realm);
        List<FederatedIdentityRepresentation> socialLinkReps = mapList(socialLinks, ExportUtils::exportSocialLink);
        whenNotEmpty(socialLinkReps, userRep::setFederatedIdentities);

        // Role mappings
        if (options.isGroupsAndRolesIncluded()) {
            Set<RoleModel> roles = session.userFederatedStorage().getRoleMappings(realm, id);
            List<String> realmRoleNames = new ArrayList<>();
            Map<String, List<String>> clientRoleNames = new HashMap<>();
            for (RoleModel role : roles) {
                if (role.getContainer() instanceof RealmModel) {
                    realmRoleNames.add(role.getName());
                } else {
                    ClientModel client = (ClientModel) role.getContainer();
                    String clientId = client.getClientId();
                    List<String> currentClientRoles = clientRoleNames.computeIfAbsent(clientId, key -> new ArrayList<>());
                    currentClientRoles.add(role.getName());
                }
            }

            if (!realmRoleNames.isEmpty()) {
                userRep.setRealmRoles(realmRoleNames);
            }
            if (!clientRoleNames.isEmpty()) {
                userRep.setClientRoles(clientRoleNames);
            }
        }

        // Credentials
        List<CredentialModel> creds = session.userFederatedStorage().getStoredCredentials(realm, id);
        List<CredentialRepresentation> credReps = mapList(creds, ExportUtils::exportCredential);
        userRep.setCredentials(credReps);

        // Grants
        List<UserConsentModel> consents = session.users().getConsents(realm, id);
        LinkedList<UserConsentRepresentation> consentReps = mapLinkedList(consents, ModelToRepresentation::toRepresentation);
        whenNotEmpty(consentReps, userRep::setClientConsents);

        // Not Before
        int notBefore = session.userFederatedStorage().getNotBeforeOfUser(realm, userRep.getId());
        userRep.setNotBefore(notBefore);

        if (options.isGroupsAndRolesIncluded()) {
            List<String> groups = mapLinkedList(session.userFederatedStorage().getGroups(realm, id), ModelToRepresentation::buildGroupPath);
            userRep.setGroups(groups);
        }
        return userRep;
    }
}
