CDAP Authorization Extension using Keycloak
------------------------------------------------

Building and installing
=======================

1. mvn  clean package -DskipTests -Drat.ignoreErrors=true -Dcheckstyle.skip=true

2. Copy the JAR file cdap-keycloak-authorizer/target/cdap-keycloak-authorizer-<version>.jar  to a more specific folder in cdap    master ex-: /opt/cdap/master/ext/security/

3. Edit the CDAP configuration in Ambari Admin UI and add the following in the custom cdap-site.xml section

::
    
    security.authorization.extension.jar.path=/opt/cdap/master/ext/security/cdap-keycloak-authorizer-<version>.jar
