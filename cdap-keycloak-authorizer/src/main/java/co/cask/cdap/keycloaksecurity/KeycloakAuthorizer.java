package co.cask.cdap.keycloaksecurity;

import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;

import co.cask.cdap.proto.id.EntityId;
import co.cask.cdap.proto.security.*;
import co.cask.cdap.security.spi.authorization.AbstractAuthorizer;
import co.cask.cdap.security.spi.authorization.AuthorizationContext;
import co.cask.cdap.security.spi.authorization.UnauthorizedException;
import org.json.JSONObject;
import org.json.XML;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.resource.ProtectedResource;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;

//import co.cask.cdap.security.server.KeycloakConfDeployment;

public class KeycloakAuthorizer extends AbstractAuthorizer {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthorizer.class);

    public KeycloakAuthorizer(){
    }

    public void initialize(AuthorizationContext context) throws Exception {
        System.out.println("initializing ...");
    }


    @Override
    public void enforce(EntityId entity, Principal principal, Action action) throws Exception {
        Set <Action> scopes = new HashSet();
        scopes.add(action);
        //Token is explicitly pass null as authorization changes not done in build
        if(!enforce(entity.getEntityName(),scopes,null)){
            throw new UnauthorizedException(principal, action, entity);
        }
    }

    //    @Override
    public void enforce(EntityId entity, Principal principal, Set<Action> set) throws Exception {
        LOG.debug("Enforce called on entity {}, principal {}, actions {}", entity, principal, set);
        //TODO: Investigate if its possible to make the enforce call with set of actions rather than one by one
        if(!enforce(entity.getEntityName(),set, null)){
            throw new UnauthorizedException(principal, set, entity);
        }
    }

    public boolean enforce(String resource, Set <Action> scopes , String accessToken) throws ClassNotFoundException{
        List <String> scopeList = new ArrayList();
        for(Action action : scopes){
            scopeList.add(action.toString());
        }
        boolean isAllowed = true;
        isAllowed = requestTokenAuthorization(resource,scopeList,accessToken);
        return isAllowed;
    }


    public Set<? extends EntityId> isVisible(Set<? extends EntityId> entityIds, Principal principal) throws Exception {
        //throw new UnsupportedOperationException("Visibility check is not supported via keycloak");
        Set<EntityId> visibleEntities = new HashSet(entityIds.size());
        for (EntityId entityId : entityIds) {
            visibleEntities.add(entityId);
        }
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

    public  boolean requestTokenAuthorization(String resource , List<String> scopes, String keycloakToken) {

        try {

            AuthorizationRequest authzRequest1 = new AuthorizationRequest();
            if(authzRequest1!=null)
                System.out.println("bsnsbcncnbc");

            String path = Thread.currentThread().getContextClassLoader().getResource("cdap-site.xml").getPath();
            InputStream is = createKeycloakDeployment(path);
            KeycloakDeployment deployment = KeycloakDeploymentBuilder.build(is);


            AuthzClient authzClient = AuthzClient.create(is);
            AuthorizationRequest authzRequest = new AuthorizationRequest();

            AuthorizationResponse authzResponse;

            ProtectedResource resourceClient = authzClient.protection().resource();
            ResourceRepresentation existingResource = resourceClient.findByName(resource);
            authzRequest.addPermission(existingResource.getId(),scopes);

            authzResponse = authzClient.authorization(keycloakToken).authorize(authzRequest);

            if (authzResponse != null) {
              org.keycloak.representations.AccessToken rptToken =  AdapterTokenVerifier.verifyToken(authzResponse.getToken(), deployment);
              org.keycloak.representations.AccessToken.Authorization authorization = rptToken.getAuthorization();

                if (authorization != null) {
                    Collection<Permission> grantedPermissions= authorization.getPermissions();
                    Permission resourcePermission = grantedPermissions.iterator().next();
                    if(resourcePermission.getResourceId() == resource && resourcePermission.getScopes().containsAll(scopes)){
                        return true;
                    }
                }
            }
        } catch (AuthorizationDeniedException ignore) {
            //LOGGER.debug("Authorization denied", ignore);
            throw new RuntimeException("Unexpected error during authorization request.", ignore);

        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during authorization request.", e);
        }
        return true;
    }


    public static InputStream createKeycloakDeployment(String Configfile){

        try {
            File xmlFile = new File(Configfile);
            Reader fileReader = new FileReader(xmlFile);
            BufferedReader bufReader = new BufferedReader(fileReader);
            boolean flag = false;
            StringBuilder sb = new StringBuilder();
            String line = bufReader.readLine().trim();
            while (line != null) {
                if (line.endsWith("</keycloakConfiguration>")) {
                    flag = false;
                    break;
                }
                if (line.endsWith("<keycloakConfiguration>") || flag == true) {
                    if(flag)
                        sb.append(line).append("\n");
                    flag=true;
                }
                line = bufReader.readLine().trim();
            }

            if(sb.length()!=0) {
                String xml2String = sb.toString();

                try {
                    JSONObject obj = XML.toJSONObject(xml2String);
                    String str = obj.toString();
                    InputStream is = new ByteArrayInputStream(str.getBytes());
                    return is;
                }
                catch (Exception ex){
                    throw new RuntimeException("error in converting xml to json");
                }
            }
            else{
                throw new RuntimeException("Keycloak configuration is not defined");
            }

        }
        catch(Exception ex){
            throw new RuntimeException(ex.getMessage());
        }
    }
}
