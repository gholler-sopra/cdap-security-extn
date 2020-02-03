package co.cask.cdap.keycloaksecurity;

import co.cask.cdap.proto.id.*;
import co.cask.cdap.proto.element.EntityType;
import co.cask.cdap.proto.security.*;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.LoadingCache;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.representation.TokenIntrospectionResponse;
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
    KeycloakAuthUtil authutil;
    private static LoadingCache<String, ResourceRepresentation> resourceCache;


    public KeycloakAuthorizer() {
    }

    public void initialize(AuthorizationContext context) {
        System.out.println("initializing keycloak Authorization instance....");
        properties = context.getExtensionProperties();
        InputStream is = createConfiguration(context);
        instanceName = properties.containsKey("instance.name") ?
                properties.getProperty("instance.name") : "cdap";
        authzClient = AuthzClient.create(is);
        authutil = new KeycloakAuthUtil(authzClient);
        resourceCache = authutil.createResourceCache();
    }


    @Override
    public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
        Set<Action> scopes = new HashSet();
        scopes.add(action);
        if (!enforce(entity, scopes, principal)) {
            throw new UnauthorizedException(principal, action, entity);
        }
    }

    public void enforce(EntityId entity, Principal principal, Set<Action> set) throws Exception {
        LOG.debug("Enforce called on entity {}, principal {}, actions {}", entity, principal, set);
        //TODO: Investigate if its possible to make the enforce call with set of actions rather than one by one
        if (!enforce(entity, set, principal)) {
            throw new UnauthorizedException(principal, set, entity);
        }
    }

    public boolean enforce(EntityId entityId, Set<Action> scopes, Principal principal) {
        List<String> scopeList = new ArrayList();
        for (Action action : scopes) {
            scopeList.add(action.toString());
        }
        boolean isAllowed = requestTokenAuthorization(entityId, scopeList, principal, true);
        return isAllowed;
    }


    public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {
        ArrayList<String> scopes = new ArrayList<String>(Arrays.asList("READ", "WRITE", "EXECUTE", "ADMIN"));
        Map<EntityId, List<String>> resourceMap = new HashMap();
        for (EntityId entityId : entityIds) {
            resourceMap.put(entityId, scopes);
        }
        Set<EntityId> visibleEntities = getAccessibleEntities(resourceMap, principal, false);

        return visibleEntities;
    }

    public void grant(Authorizable authorizable, Principal principal, Set<Action> set) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public void revoke(Authorizable authorizable, Principal principal, Set<Action> set) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public void revoke(Authorizable authorizable) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public void createRole(Role role) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public void dropRole(Role role) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public void addRoleToPrincipal(Role role, Principal principal) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");

    }

    public void removeRoleFromPrincipal(Role role, Principal principal) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");

    }

    public Set<Role> listRoles(Principal principal) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public Set<Role> listAllRoles() {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }

    public Set<Privilege> listPrivileges(Principal principal) {
        throw new UnsupportedOperationException("Please use Keycloak Admin UI.");
    }


    private boolean requestTokenAuthorization(EntityId entityId, List<String> scopes, Principal principal, boolean isAllScopesMandatory) {
        try {
            Map<EntityId, List<String>> resourceMap = new HashMap();
            resourceMap.put(entityId, scopes);
            Set<EntityId> accessibleEntity = getAccessibleEntities(resourceMap, principal, isAllScopesMandatory);
            if (!accessibleEntity.isEmpty())
                return true;
        } catch (AuthorizationDeniedException ignore) {
            throw new RuntimeException("Unexpected error during authorization request.", ignore);

        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during authorization request.", e);
        }
        return false;
    }


    private Set<EntityId> getAccessibleEntities(Map<EntityId, List<String>> resourceMap, Principal principal, boolean isAllScopesMandatory) {
        String keycloakToken = authutil.getKeycloakToken(principal.getAccessToken());
        AuthorizationRequest authzRequest = new AuthorizationRequest();
        Boolean exceptionFlag = false;
        Set<EntityId> visibleEntities = new HashSet();
        try {
            if (keycloakToken == null) {
                throw new UnauthorizedException("keycloak token is null");
            }

            if (resourceMap.isEmpty())
                return Collections.EMPTY_SET;

            String resourceUrl;
            AuthorizationResponse authzResponse;

            Map<String, EntityId> resourceEntityMap = new HashMap();

            for (Map.Entry<EntityId, List<String>> resource : resourceMap.entrySet()) {
                resourceUrl = getResourceURL(resource.getKey());
                ResourceRepresentation existingResource = resourceCache.get(resourceUrl);

                if (existingResource.getId() != null) {
                    resourceEntityMap.put(existingResource.getId(), resource.getKey());
                    authzRequest.addPermission(existingResource.getId(), resource.getValue());
                }
            }

            List<Permission> requiredPermissions = authzRequest.getPermissions().getPermissions();
            Collection<Permission> grantedPermissions;
            if (requiredPermissions != null && !requiredPermissions.isEmpty()) {
                authzResponse = authzClient.authorization(keycloakToken).authorize(authzRequest);
                TokenIntrospectionResponse requestingPartyToken = authzClient.protection().introspectRequestingPartyToken(authzResponse.getToken());
                if (requestingPartyToken != null) {
                    grantedPermissions = requestingPartyToken.getPermissions();
                    Iterator<Permission> permissionIterator = grantedPermissions.iterator();
                    while (permissionIterator.hasNext()) {
                        Permission permission = permissionIterator.next();
                        String resourceId = permission.getResourceId();
                        Set<String> scopeSet = permission.getScopes();
                        List<String> scopeList = new ArrayList<>();
                        scopeList.addAll(scopeSet);

                        if (!isAllScopesMandatory) {
                            visibleEntities.add(resourceEntityMap.get(resourceId));
                        } else if (resourceMap.get(resourceEntityMap.get(resourceId)).equals(scopeList)) {
                            visibleEntities.add(resourceEntityMap.get(resourceId));
                        }
                    }
                }
            }
        } catch (AuthorizationDeniedException ignore) {

        } catch (Exception e) {

        } finally {
            if (visibleEntities.isEmpty())
                visibleEntities = Collections.EMPTY_SET;
            return visibleEntities;
        }
    }

    public String getResourceURL(EntityId entityId) {
        EntityType entityType = entityId.getEntityType();
        String resourcePrefix = "/cdap/instances/";
        String resourceUrl;
        switch (entityType.name()) {
            case "INSTANCE":
                resourceUrl = resourcePrefix + instanceName;
                break;
            case "NAMESPACE":
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + entityId.getEntityName();
                break;
            case "ARTIFACT":
                ArtifactId artifactId = (ArtifactId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + artifactId.getNamespace() + "/artifacts/" + artifactId.getArtifact();
                break;
            case "APPLICATION":
                ApplicationId applicationId = (ApplicationId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + applicationId.getNamespace() + "/apps/" + applicationId.getApplication();
                break;
            case "DATASET":
                DatasetId dataset = (DatasetId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + dataset.getNamespace() + "/data/datasets/" + dataset.getDataset();
                break;
            case "DATASET_MODULE":
                DatasetModuleId datasetModuleId = (DatasetModuleId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + datasetModuleId.getNamespace() + "/datasetmodules/" + datasetModuleId.getModule();
                break;
            case "DATASET_TYPE":
                DatasetTypeId datasetTypeId = (DatasetTypeId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + datasetTypeId.getNamespace() + "/data/datasettypes/" + datasetTypeId.getType();
                break;
            case "STREAM":
                StreamId streamId = (StreamId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + streamId.getNamespace() + "/streams/" + streamId.getEntityName();
                break;
            case "PROGRAM":
                ProgramId programId = (ProgramId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + programId.getNamespace() + "/applications/" + programId.getApplication() + "/programs/" + programId.getProgram();
                break;
            case "SECUREKEY":
                SecureKeyId secureKeyId = (SecureKeyId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/namespaces/" + secureKeyId.getNamespace() + "/securekeys/" + secureKeyId.getName();
                break;
            case "KERBEROSPRINCIPAL":
                KerberosPrincipalId kerberosPrincipalId = (KerberosPrincipalId) entityId;
                resourceUrl = resourcePrefix + instanceName + "/kerberosprincipals/" + kerberosPrincipalId.getPrincipal();
                break;
            default:
                throw new IllegalArgumentException(String.format("The entity %s is of unknown type %s", entityId, entityType));
        }
        return resourceUrl;
    }

    private InputStream createConfiguration(AuthorizationContext context) {
        Properties extensionProp = context.getExtensionProperties();
        String JsonElem;
        InputStream inputStream;
        try {

            if (extensionProp.contains("keycloak-config-file")) {
                String filePath = extensionProp.get("keycloak-config-file").toString();
                File keycloakConfigFile = new File(filePath);
                if (keycloakConfigFile.exists()) {
                    inputStream = new FileInputStream(keycloakConfigFile);
                    return inputStream;
                }
            }

            String clientId = extensionProp.getProperty("client_id");
            String clientSecret = extensionProp.getProperty("client_secret");
            String realm = extensionProp.getProperty("realm");
            String keycloakauthserveraddress = extensionProp.getProperty("keycloakauthserveraddress");
            String keycloakauthserverport = extensionProp.getProperty("keycloakauthserverport");
            String authServerUrl = "http://" + keycloakauthserveraddress + ":" + keycloakauthserverport + "/auth";

            Map<String, Object> clientCredentials = new HashMap();
            clientCredentials.put("secret", clientSecret);
            Configuration keycloakConf = new Configuration(authServerUrl, realm, clientId, clientCredentials, null);
            ObjectMapper objectMapper = new ObjectMapper();

            JsonElem = objectMapper.writeValueAsString(keycloakConf);
            System.out.println(JsonElem);
        } catch (Exception ex) {
            throw new RuntimeException("unable to convert to Json");
        }

        inputStream = new ByteArrayInputStream(JsonElem.getBytes());
        return inputStream;
    }

//    public void updatePermissionBasedCache(List<Permission> permissions , boolean isAllScopesMandatory , String username){
//        Iterator<Permission> permissionIterator = permissions.iterator();
//        while (permissionIterator.hasNext()) {
//            Permission permission = permissionIterator.next();
//            String resourceId = permission.getResourceId();
//            Set<String> scopeSet = permission.getScopes();
//            String userResourcePrefix = username + "_" + resourceId;
//            if (!isAllScopesMandatory)
//                userResourceAccessCache.put(userResourcePrefix, false);
//            for (String scope : scopeSet) {
//                userResourceAccessCache.put(userResourcePrefix + "_" + scope, false);
//            }
//        }
//
//    }

}