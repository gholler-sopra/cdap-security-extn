package co.cask.cdap.keycloaksecurity;

import co.cask.cdap.proto.id.*;
import co.cask.cdap.proto.security.*;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
import org.keycloak.authorization.client.resource.ProtectedResource;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

public class KeycloakAuthorizer extends AbstractAuthorizer {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthorizer.class);
    private static AuthzClient authzClient;
    private static Properties properties;
    private String instanceName;
    Map<String, Integer> entityMap;

    public KeycloakAuthorizer() {
    }

    public void initialize(AuthorizationContext context) throws Exception {
        System.out.println("initializing ...");
        properties = context.getExtensionProperties();
        InputStream is = createConfigration(context);
        instanceName = properties.containsKey("instance.name") ?
                properties.getProperty("instance.name") : "cdap";
        authzClient = AuthzClient.create(is);
        entityMap = new HashMap<String, Integer>();
        entityMap.put("INSTANCE", 1);
        entityMap.put("NAMESPACE", 2);
        entityMap.put("ARTIFACT", 3);
        entityMap.put("APPLICATION", 4);
        entityMap.put("DATASET", 5);
        entityMap.put("DATASET_MODULE", 6);
        entityMap.put("DATASET_TYPE", 7);
        entityMap.put("PROGRAM", 8);
        entityMap.put("SECUREKEY", 9);
        entityMap.put("KERBEROSPRINCIPAL", 10);
    }


    @Override
    public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
        Set<Action> scopes = new HashSet();
        scopes.add(action);
        if (!enforce(entity, scopes, principal.getAccessToken())) {
            throw new UnauthorizedException(principal, action, entity);
        }
    }

    public void enforce(EntityId entity, Principal principal, Set<Action> set) throws Exception {
        LOG.debug("Enforce called on entity {}, principal {}, actions {}", entity, principal, set);
        //TODO: Investigate if its possible to make the enforce call with set of actions rather than one by one
        if (!enforce(entity, set, principal.getAccessToken())) {
            throw new UnauthorizedException(principal, set, entity);
        }
    }

    public boolean enforce(EntityId entityId, Set<Action> scopes, String accessToken) {
        List<String> scopeList = new ArrayList();
        for (Action action : scopes) {
            scopeList.add(action.toString());
        }
//        boolean isAllowed = isEntityAccessible(entityId, scopeList, accessToken);
        String resourceUrl = getResourceURL(entityId);
        boolean isAllowed = requestTokenAuthorization(resourceUrl, scopeList, accessToken);
        return isAllowed;
    }


    public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {
        ArrayList<String> scopes = new ArrayList<String>(Arrays.asList("READ", "WRITE", "EXECUTE", "ADMIN"));
        Map<EntityId, List<String>> resourceMap = new HashMap();
        for (EntityId entityId : entityIds) {
            resourceMap.put(entityId, scopes);
        }
        Set<EntityId> visibleEntities = getVisibleEntities(resourceMap, principal.getAccessToken());

        return visibleEntities;
    }

    public void grant(Authorizable authorizable, Principal principal, Set<Action> set) {
        throw new UnsupportedOperationException("Please use Ranger Admin UI to grant privileges.");
    }

    public void revoke(Authorizable authorizable, Principal principal, Set<Action> set) {
        throw new UnsupportedOperationException("Please use Ranger Admin UI to revoke privileges.");
    }

    public void revoke(Authorizable authorizable) {
        throw new UnsupportedOperationException("Please use Ranger Admin UI to revoke privileges.");
    }

    public void createRole(Role role) {
        throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
    }

    public void dropRole(Role role) {
        throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
    }

    public void addRoleToPrincipal(Role role, Principal principal) {
        throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");

    }

    public void removeRoleFromPrincipal(Role role, Principal principal) {
        throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");

    }

    public Set<Role> listRoles(Principal principal) {
        throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
    }

    public Set<Role> listAllRoles() {
        throw new UnsupportedOperationException("Roles are not supported in Ranger plugin.");
    }

    public Set<Privilege> listPrivileges(Principal principal) {
        throw new UnsupportedOperationException("Please use Ranger Admin UI to list privileges.");
    }


    private boolean requestTokenAuthorization(String resource, List<String> scopes, String keycloakToken) {

        try {
            if (keycloakToken == null) {
                return false;
            }

            AuthorizationRequest authzRequest = new AuthorizationRequest();
            AuthorizationResponse authzResponse;
            ProtectedResource resourceClient = authzClient.protection().resource();
            ResourceRepresentation existingResource = resourceClient.findByMatchingUri(resource).get(0);
            authzRequest.addPermission(existingResource.getId(), scopes);
            authzResponse = authzClient.authorization(keycloakToken).authorize(authzRequest);
            if (authzResponse != null) {
                TokenIntrospectionResponse requestingPartyToken = authzClient.protection().introspectRequestingPartyToken(authzResponse.getToken());
                if (requestingPartyToken != null) {
                    Collection<Permission> grantedPermissions = requestingPartyToken.getPermissions();
                    Permission resourcePermission = grantedPermissions.iterator().next();
                    if (resourcePermission.getResourceId().equals(existingResource.getId()) && resourcePermission.getScopes().containsAll(scopes)) {
                        return true;
                    }
                }
            }
        } catch (AuthorizationDeniedException ignore) {
            throw new RuntimeException("Unexpected error during authorization request.", ignore);

        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during authorization request.", e);
        }
        return false;
    }


    private Set getVisibleEntities(Map<EntityId, List<String>> resourceMap, String keycloakToken) {

        try {
            if (keycloakToken == null) {
                throw new RuntimeException("token is not available");
            }

            if (resourceMap.isEmpty())
                return Collections.EMPTY_SET;

            String resourceUrl;
            Set<EntityId> visibleEntities = new HashSet();
            AuthorizationRequest authzRequest = new AuthorizationRequest();
            AuthorizationResponse authzResponse;
            ProtectedResource resourceClient = authzClient.protection().resource();

            Map<String, EntityId> resourceEntityMap = new HashMap();

            for (Map.Entry<EntityId, List<String>> resource : resourceMap.entrySet()) {
                resourceUrl = getResourceURL(resource.getKey());
                List<ResourceRepresentation> existingResources = resourceClient.findByMatchingUri(resourceUrl);
                if (existingResources != null && !existingResources.isEmpty()) {
                    ResourceRepresentation existingResource = existingResources.get(0);
                    resourceEntityMap.put(existingResource.getId(), resource.getKey());
                    authzRequest.addPermission(existingResource.getId(), resource.getValue());
                }
            }
            if (authzRequest.getPermissions().getPermissions() != null) {
                authzResponse = authzClient.authorization(keycloakToken).authorize(authzRequest);
                TokenIntrospectionResponse requestingPartyToken = authzClient.protection().introspectRequestingPartyToken(authzResponse.getToken());
                if (requestingPartyToken != null) {
                    Collection<Permission> grantedPermissions = requestingPartyToken.getPermissions();
                    Iterator<Permission> permissionIterator = grantedPermissions.iterator();
                    while (permissionIterator.hasNext()) {
                        String resourceId = permissionIterator.next().getResourceId();
                        if (resourceEntityMap.containsKey(resourceId))
                            visibleEntities.add(resourceEntityMap.get(resourceId));

                    }
                    return visibleEntities;
                }
            }
        } catch (AuthorizationDeniedException ignore) {
            throw new RuntimeException("Authorization is denied.", ignore);

        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during authorization request.", e);
        }
        return Collections.EMPTY_SET;
    }


    public String getResourceURL(EntityId entityId) {
        String entityType = entityId.getEntityType().name();
        String resourceUrl;
        switch (entityMap.get(entityType)) {
            case 1:
                resourceUrl = "instance/";
                break;
            case 2:
                resourceUrl = "instance/" + instanceName + "/namespace/" + entityId.getEntityName();
                break;
            case 3:
                ArtifactId artifactId = (ArtifactId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + artifactId.getNamespace() + "/artifact/" + artifactId.getArtifact();
                break;
            case 4:
                ApplicationId applicationId = (ApplicationId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + applicationId.getNamespace() + "/application/" + applicationId.getApplication();
                break;
            case 5:
                DatasetId dataset = (DatasetId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + dataset.getNamespace() + "/application/" + dataset.getDataset();
                break;
            case 6:
                DatasetModuleId datasetModuleId = (DatasetModuleId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + datasetModuleId.getNamespace() + "/datasetmodule/" + datasetModuleId.getModule();
                break;
            case 7:
                DatasetTypeId datasetTypeId = (DatasetTypeId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + datasetTypeId.getNamespace() + "/datasettype/" + datasetTypeId.getType();
                break;
            case 8:
                ProgramId programId = (ProgramId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + programId.getNamespace() + "/application/" + programId.getApplication() + "/program/" + programId.getProgram();
                break;
            case 9:
                SecureKeyId secureKeyId = (SecureKeyId) entityId;
                resourceUrl = "instance/" + instanceName + "/namespace/" + secureKeyId.getNamespace() + "/securekey/" + secureKeyId.getName();
                break;
            case 10:
                KerberosPrincipalId kerberosPrincipalId = (KerberosPrincipalId) entityId;
                resourceUrl = "instance/" + instanceName + "/kerberosprincipal/" + kerberosPrincipalId.getPrincipal();
                break;
            default:
                throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
        }

        return resourceUrl;
    }

    private InputStream createConfigration(AuthorizationContext context) {
        Properties extensionProp = context.getExtensionProperties();
        String JsonElem;
        String clientId = extensionProp.getProperty("client_id");
        String clientSecret = extensionProp.getProperty("client_secret");
        String realm = extensionProp.getProperty("realm");
        String authServerUrl = extensionProp.getProperty("authserverurl");

        Map<String, Object> clientCredentials = new HashMap();
        clientCredentials.put("secret", clientSecret);
        Configuration keycloakConf = new Configuration(authServerUrl, realm, clientId, clientCredentials, null);
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            JsonElem = objectMapper.writeValueAsString(keycloakConf);
            System.out.println(JsonElem);
        } catch (Exception ex) {
            throw new RuntimeException("unable to convert to Json");
        }

        InputStream inputStream = new ByteArrayInputStream(JsonElem.getBytes());
        return inputStream;
    }
}