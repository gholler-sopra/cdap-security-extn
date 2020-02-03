package co.cask.cdap.keycloaksecurity;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.apache.commons.codec.binary.Base64;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.resource.ProtectedResource;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;

import java.util.List;
import java.util.concurrent.TimeUnit;

public class KeycloakAuthUtil {

    protected AuthzClient authzClient;
    protected ProtectedResource resourceClient;

    KeycloakAuthUtil(AuthzClient authzClient) {
        this.authzClient = authzClient;
        this.resourceClient = authzClient.protection().resource();
    }


    protected String getKeycloakToken(String cdapToken) {
        String accessToken = new String(Base64.decodeBase64(cdapToken));
        String[] tempElem = accessToken.split("\\�");
        String keycloakToken = (tempElem[1].trim()).replaceAll("[^\\p{ASCII}]", "");
        return keycloakToken;
    }

    protected LoadingCache<String, ResourceRepresentation> createResourceCache() {
        return CacheBuilder.newBuilder()
                .maximumSize(10000)
                .expireAfterAccess(2, TimeUnit.MINUTES)
                .build(new CacheLoader<String, ResourceRepresentation>() {

                    @Override
                    public ResourceRepresentation load(String URI) throws Exception {
                        //make the expensive call
                        return getResourceFromKeycloak(URI);
                    }
                });
    }

    private ResourceRepresentation getResourceFromKeycloak(String uri) {
        System.out.println("Database hit for" + uri);
        List<ResourceRepresentation> resourceList = resourceClient.findByMatchingUri(uri);
        if (!resourceList.isEmpty())
            return resourceList.get(0);

        return new ResourceRepresentation();
    }
}
