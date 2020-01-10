package co.cask.cdap.keycloaksecurity;

import org.apache.commons.codec.binary.Base64;

public class KeycloakAuthUtil {

    public static String getKeycloakToken(String cdapToken){
        String accessToken = new String(Base64.decodeBase64(cdapToken));
        String [] tempElem = accessToken.split("\\?");
        String keycloakToken = (tempElem[1].trim()).replaceAll("[^\\p{ASCII}]", "");
        return keycloakToken;
    }
}
