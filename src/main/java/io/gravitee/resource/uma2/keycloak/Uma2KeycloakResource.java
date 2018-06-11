/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.uma2.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.resource.oauth2.api.OAuth2Resource;
import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.oauth2.api.openid.UserInfoResponse;
import io.gravitee.resource.uma2.keycloak.adapters.KeycloakDeploymentBuilder;
import io.gravitee.resource.uma2.keycloak.configuration.Uma2KeycloakResourceConfiguration;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import org.keycloak.RSATokenVerifier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class Uma2KeycloakResource extends OAuth2Resource<Uma2KeycloakResourceConfiguration> implements ApplicationContextAware {

    private final Logger logger = LoggerFactory.getLogger(Uma2KeycloakResource.class);

    private final static String KEYCLOAK_INTROSPECTION_ENDPOINT = "/protocol/openid-connect/token/introspect";
    private final static String KEYCLOAK_USERINFO_ENDPOINT = "/protocol/openid-connect/userinfo";
    private final static String KEYCLOAK_AUTHORIZE_ENDPOINT = "/protocol/openid-connect/token";
    public static final String DEFAULT_TENANT = "Default";

    private static final String HTTPS_SCHEME = "https";

    private static final String AUTHORIZATION_HEADER_BASIC_SCHEME = "Basic ";
    private static final String AUTHORIZATION_HEADER_BEARER_SCHEME = "Bearer ";
    private static final char AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR = ':';

    private ApplicationContext applicationContext;

    private final Map<Context, HttpClient> httpClients = new HashMap<>();

    private HttpClientOptions httpClientOptions;
    
    private HttpClientOptions httpAuditClientOptions;

    private Vertx vertx;

    private String introspectionEndpointURI;
    private String authorizationHeaderIntrospect;
    private String userInfoEndpointURI;
    private String authorizationEndpointURI;
    private String auditEndpointURI;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PublicKey publicKey;
    private String realmUrl;
    private AuthzClient authzClient;
    
    Map<String,Map<String, ResourceRepresentation>> resourceCache;
    
    
	public AuthzClient getAuthzClient() {
		return authzClient;
	}

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        logger.info("Starting a Keycloak Adapter resource");

        AdapterConfig adapterConfig = KeycloakDeploymentBuilder.loadAdapterConfig(
                configuration().getKeycloakConfiguration());

        publicKey = PemUtils.decodePublicKey(adapterConfig.getRealmKey());
        realmUrl = adapterConfig.getAuthServerUrl() + "/realms/" + adapterConfig.getRealm();

        URI introspectionUri = URI.create(realmUrl);

        int authorizationServerPort = introspectionUri.getPort() != -1 ? introspectionUri.getPort() :
                (HTTPS_SCHEME.equals(introspectionUri.getScheme()) ? 443 : 80);
        String authorizationServerHost = introspectionUri.getHost();

//        ProxyOptions proxyOptions= new ProxyOptions();
//        proxyOptions.setHost("127.0.0.1");
//        proxyOptions.setPort(8080);
//        
        httpClientOptions = new HttpClientOptions()
                .setDefaultPort(authorizationServerPort)
                .setDefaultHost(authorizationServerHost);
//                .setProxyOptions(proxyOptions);

        // Use SSL connection if authorization schema is set to HTTPS
        if (HTTPS_SCHEME.equalsIgnoreCase(introspectionUri.getScheme())) {
            httpClientOptions
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true);
        }

        authorizationHeaderIntrospect = AUTHORIZATION_HEADER_BASIC_SCHEME +
                Base64.getEncoder().encodeToString(
                        (adapterConfig.getResource() + AUTHORIZATION_HEADER_VALUE_BASE64_SEPARATOR +
                                adapterConfig.getCredentials().get("secret")).getBytes());

        // Prepare userinfo endpoint calls
        userInfoEndpointURI = introspectionUri.getPath() + KEYCLOAK_USERINFO_ENDPOINT;

        // Prepare introspection endpoint calls
        introspectionEndpointURI = introspectionUri.getPath() + KEYCLOAK_INTROSPECTION_ENDPOINT;
        
        authorizationEndpointURI = introspectionUri.getPath() + KEYCLOAK_AUTHORIZE_ENDPOINT;

        vertx = applicationContext.getBean(Vertx.class);
        
        authzClient = AuthzClient.create(JsonSerialization.readValue(configuration().getKeycloakConfiguration(), Configuration.class));
        
        resourceCache = Collections.synchronizedMap(new HashMap<String,Map<String, ResourceRepresentation>>());
        
        URI auditURI = URI.create(configuration().getAuditEndpoint());
        
        int auditServerPort = auditURI.getPort() != -1 ? auditURI.getPort() :
            (HTTPS_SCHEME.equals(auditURI.getScheme()) ? 443 : 80);
        String auditServerHost = auditURI.getHost();
        
        httpAuditClientOptions = new HttpClientOptions()
                .setDefaultPort(auditServerPort)
                .setDefaultHost(auditServerHost);
//                .setProxyOptions(proxyOptions);

        // Use SSL connection if authorization schema is set to HTTPS
        if (HTTPS_SCHEME.equalsIgnoreCase(auditURI.getScheme())) {
            httpAuditClientOptions
                    .setSsl(true)
                    .setVerifyHost(false)
                    .setTrustAll(true);
        }
        
        auditEndpointURI = auditURI.getPath();
        
        logger.debug( auditEndpointURI );
        
        logger.debug(auditServerHost);
        
        logger.debug("port: " + auditServerPort);
        
        updateResourceCache();
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        httpClients.values().forEach(httpClient -> {
            try {
                httpClient.close();
            } catch (IllegalStateException ise) {
                logger.warn(ise.getMessage());
            }
        });
    }

    @Override
    public void introspect(String accessToken, Handler<OAuth2Response> responseHandler) {
        if (publicKey != null) {
            try {
                AccessToken token = RSATokenVerifier.verifyToken(accessToken, publicKey, realmUrl);
                responseHandler.handle(new OAuth2Response(true, MAPPER.writeValueAsString(token)));
            } catch (VerificationException ve) {
                logger.error("Unable to verify access token", ve);
                responseHandler.handle(new OAuth2Response(false, "{\"error\": \"access_denied\"}"));
            } catch (JsonProcessingException jpe) {
                logger.error("Unable to transform access token", jpe);
            }
        } else {
            HttpClient httpClient = httpClients.computeIfAbsent(
                    Vertx.currentContext(), context -> vertx.createHttpClient(httpClientOptions));

            logger.debug("Introspect access token by requesting {}", introspectionEndpointURI);

            HttpClientRequest request = httpClient.post(introspectionEndpointURI);

            request.headers().add(HttpHeaders.AUTHORIZATION, authorizationHeaderIntrospect);
            request.headers().add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
            request.headers().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);

            request.handler(response -> response.bodyHandler(buffer -> {
                logger.debug("Keycloak introspection endpoint returns a response with a {} status code", response.statusCode());
                String body = buffer.toString();
                if (response.statusCode() == HttpStatusCode.OK_200) {
                    JsonNode introspectPayload = readPayload(body);
                    boolean active = introspectPayload.path("active").asBoolean(false);
                    if (active) {
                        responseHandler.handle(new OAuth2Response(true, body));
                    } else {
                        responseHandler.handle(new OAuth2Response(false, "{\"error\": \"access_denied}\""));
                    }
                } else {
                    responseHandler.handle(new OAuth2Response(false, body));
                }
            }));

            request.exceptionHandler(event -> {
                logger.error("An error occurs while introspecting access token", event);
                responseHandler.handle(new OAuth2Response(false, event.getMessage()));
            });

            request.end("token=" + accessToken);
        }
    }
    
    public void exchange(String accessToken, String targetClient, String scope, Handler<OAuth2Response> responseHandler) {
        if (publicKey != null) {
            try {
                AccessToken token = RSATokenVerifier.verifyToken(accessToken, publicKey, realmUrl);
                responseHandler.handle(new OAuth2Response(true, MAPPER.writeValueAsString(token)));
            } catch (VerificationException ve) {
                logger.error("Unable to verify access token", ve);
                responseHandler.handle(new OAuth2Response(false, "{\"error\": \"access_denied\"}"));
            } catch (JsonProcessingException jpe) {
                logger.error("Unable to transform access token", jpe);
            }
        } else {
            HttpClient httpClient = httpClients.computeIfAbsent(
                    Vertx.currentContext(), context -> vertx.createHttpClient(httpClientOptions));

            logger.debug("Exchange access token by requesting {}", introspectionEndpointURI);

            logger.debug("Introspect access token by requesting {}", authorizationEndpointURI);

            HttpClientRequest request = httpClient.post(authorizationEndpointURI);
            
            request.headers().add(HttpHeaders.AUTHORIZATION, authorizationHeaderIntrospect);
            request.headers().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
            
            request.handler(response -> response.bodyHandler(buffer -> {
                logger.debug("Keycloak introspection endpoint returns a response with a {} status code", response.statusCode());
                String body = buffer.toString();
                if (response.statusCode() == HttpStatusCode.OK_200) {
                    JsonNode introspectPayload = readPayload(body);
                    boolean active = introspectPayload.path("active").asBoolean(false);
                    if (active) {
                        responseHandler.handle(new OAuth2Response(true, body));
                    } else {
                        responseHandler.handle(new OAuth2Response(false, "{\"error\": \"access_denied}\""));
                    }
                } else {
                    responseHandler.handle(new OAuth2Response(false, body));
                }
            }));

            request.exceptionHandler(event -> {
                logger.error("An error occurs while checking uma authorization", event);
                responseHandler.handle(new OAuth2Response(false, event.getMessage()));
            });

            String requestBody="grant_type=urn:ietf:params:oauth:grant-type:token-exchange";
            requestBody +="&requested_token_type=urn:ietf:params:oauth:token-type:refresh_token";
            if (targetClient!=null && !targetClient.equals("")) requestBody +="&audience="+targetClient;
            if (scope!=null && !scope.equals("")) requestBody +="&scope="+scope;
            
            request.end(requestBody);
        }
    }
    
    public void authorizeUma(String accessToken, String[] permissions, String audience, Handler<OAuth2Response> responseHandler) {

            HttpClient httpClient = httpClients.computeIfAbsent(
                    Vertx.currentContext(), context -> vertx.createHttpClient(httpClientOptions));

            logger.debug("Introspect access token by requesting {}", authorizationEndpointURI);

            HttpClientRequest request = httpClient.post(authorizationEndpointURI);

            request.headers().add(HttpHeaders.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);
            request.headers().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED);
            
            request.handler(response -> response.bodyHandler(buffer -> {
                logger.debug("Keycloak introspection endpoint returns a response with a {} status code", response.statusCode());
                String body = buffer.toString();
                if (response.statusCode() == HttpStatusCode.OK_200) {
                    responseHandler.handle(new OAuth2Response(true, body));
                } else {
                    responseHandler.handle(new OAuth2Response(false, body));
                }
            }));
            
            request.exceptionHandler(event -> {
                logger.error("An error occured while checking uma authorization", event);
                responseHandler.handle(new OAuth2Response(false, event.getMessage()));
            });

            String requestBody="grant_type=urn:ietf:params:oauth:grant-type:uma-ticket";
            requestBody +="&audience="+audience;
            
            for (String permission: Arrays.asList(permissions)){
            		requestBody +="&permission="+permission;
				logger.debug("adding permission to request: " + permission);
            }
            
            request.end(requestBody);
    }
    
    public void audit(String accessToken, String resourceId, Handler<OAuth2Response> responseHandler) {

        HttpClient httpClient = httpClients.computeIfAbsent(
                Vertx.currentContext(), context -> vertx.createHttpClient(httpClientOptions));
        
        String requestPath = auditEndpointURI + "/" + resourceId + "/";
        
        logger.debug("audit ping {}", requestPath);

        HttpClientRequest request = httpClient.get(httpAuditClientOptions.getDefaultPort(), httpAuditClientOptions.getDefaultHost(), requestPath);
        
        request.headers().add(HttpHeaders.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);
        
        request.handler(response -> response.bodyHandler(buffer -> {
            logger.debug("Audit endpoint returns a response with a {} status code", response.statusCode());
            String body = buffer.toString();
            if (response.statusCode() == HttpStatusCode.OK_200) {
                responseHandler.handle(new OAuth2Response(true, body));
            } else {
                responseHandler.handle(new OAuth2Response(false, body));
            }
        }));
        
        request.exceptionHandler(event -> {
            logger.error("An error occured while audit resource access", event);
            responseHandler.handle(new OAuth2Response(false, event.getMessage()));
        });

        request.end();
}

    @Override
    public void userInfo(String accessToken, Handler<UserInfoResponse> responseHandler) {
        HttpClient httpClient = httpClients.computeIfAbsent(
                Vertx.currentContext(), context -> vertx.createHttpClient(httpClientOptions));

        logger.debug("Get userinfo from {}", userInfoEndpointURI);

        HttpClientRequest request = httpClient.get(userInfoEndpointURI);

        request.headers().add(HttpHeaders.AUTHORIZATION, AUTHORIZATION_HEADER_BEARER_SCHEME + accessToken);
        request.headers().add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);

        request.handler(response -> response.bodyHandler(buffer -> {
            logger.debug("Userinfo endpoint returns a response with a {} status code", response.statusCode());

            if (response.statusCode() == HttpStatusCode.OK_200) {
                responseHandler.handle(new UserInfoResponse(true, buffer.toString()));
            } else {
                responseHandler.handle(new UserInfoResponse(false, buffer.toString()));
            }
        }));

        request.exceptionHandler(event -> {
            logger.error("An error occurs while getting userinfo from access token", event);
            responseHandler.handle(new UserInfoResponse(false, event.getMessage()));
        });

        request.end();
    }
    
	public ResourceRepresentation createResource(String tenant, String displayName, String ownerId, String uri, String type, String[] scopes, boolean ownerManagedAccess) {
		try {
			UUID id = java.util.UUID.randomUUID();
			ResourceRepresentation rr = new ResourceRepresentation();
			rr.setId(id.toString());
			rr.setName(id.toString());
			rr.setDisplayName(displayName);
			rr.setOwner(ownerId);
			rr.setUri(uri);
			rr.setType(type);
			rr.setScopes( getScopeRepresentationSet(scopes) );
			rr.setOwnerManagedAccess(ownerManagedAccess);
			Map<String,List<String>> attributes = new HashMap<>();
			List<String> values = new ArrayList<>();
			values.add(tenant);
			attributes.put("tenant", values);
			rr.setAttributes(attributes);
			String newID = authzClient.protection().resource().create(rr).getId();
			rr.setId(newID);
			addResourceCache(rr,tenant);
			return rr;
		} catch (Exception e) {
			return null;
		}
	}
	
	public void deleteResource(String uri, String tenant) {

			List<ResourceRepresentation> resources = findMatchingResource(uri, tenant, false);
			resources.forEach(resource -> {
				try {
					authzClient.protection().resource().delete(resource.getId());
					removeResourceCache(resource.getUri(),tenant);
				} catch (Exception e) {		
					e.printStackTrace();
				}
			});
	}
	
	public String[] findResource(String id, String name, String uri, String owner, String type, String scope, boolean matchingUri) throws IOException {
		return authzClient.protection().resource().find(id, name, uri, owner, type, scope, matchingUri, -1, -1);	
	}
	
	public ResourceRepresentation findResource(String id) throws IOException {
		return authzClient.protection().resource().findById(id);	
	}
	
	void updateResourceCache() throws IOException {
		String[] resources = authzClient.protection().resource().findAll();
		for(String resourceId: resources){
			ResourceRepresentation resource = authzClient.protection().resource().findById(resourceId);
			String tenant =  "";
			if(!resource.getAttributes().isEmpty() && resource.getAttributes().containsValue("tenant") && !resource.getAttributes().get("tenant").isEmpty())
				tenant = resource.getAttributes().get("tenant").get(0);
			Map<String,ResourceRepresentation> tenantMap = resourceCache.get(tenant);
			if (tenantMap == null)
				tenantMap = Collections.synchronizedMap(new HashMap<String,ResourceRepresentation>());
			tenantMap.put(resource.getUri(), resource);
			resourceCache.put(tenant, tenantMap);
		}
		logger.debug("cached updated");
	}
	
	void updateResourceCache(String subPath, String tenant) throws IOException {
		List<ResourceRepresentation> resources = authzClient.protection().resource().findByMatchingUri(subPath);
		Map<String,ResourceRepresentation> tenantMap = resourceCache.get(tenant);
		if (tenantMap == null)
			tenantMap = Collections.synchronizedMap(new HashMap<String,ResourceRepresentation>());
		
		Map<String,ResourceRepresentation> map = new HashMap<>();
		resources.stream().forEach(resource -> {
			if(!resource.getAttributes().isEmpty()
					&& resource.getAttributes().containsValue("tenant")
					&& !resource.getAttributes().get("tenant").isEmpty()
					&& resource.getAttributes().get("tenant").get(0).equals(tenant)) {				
				map.put(resource.getUri(), resource);
			}
		});
		tenantMap.putAll(map);
		resourceCache.put(tenant, tenantMap);
		logger.debug("cached updated for "+subPath);
	}
	
	void addResourceCache(ResourceRepresentation resource, String tenant) {
		Map<String,ResourceRepresentation> tenantMap = resourceCache.get(tenant);
		if (tenantMap == null)
			tenantMap = Collections.synchronizedMap(new HashMap<String,ResourceRepresentation>());
		tenantMap.put(resource.getUri(), resource);
		resourceCache.put(tenant, tenantMap);
		logger.debug("cached updated for " + resource.getId());
	}
	
	void removeResourceCache(String uri, String tenant) {
		Map<String,ResourceRepresentation> tenantMap = resourceCache.get(tenant);
		if (tenantMap != null)
			tenantMap.remove(uri);
	}
	
	public List<ResourceRepresentation> findMatchingResource(String baseUri, String tenant, boolean exactMatch) {
		List<ResourceRepresentation> results = new ArrayList<>();;
		
		if (!tenant.equals(""))
			results.addAll(findMatchingResource(baseUri, "", exactMatch));
		
		if(!resourceCache.containsKey(tenant))
			return results;
		
		Map<String,ResourceRepresentation> tenantMap = resourceCache.get(tenant);
		
		if(tenantMap.containsKey(baseUri))
			results.add(tenantMap.get(baseUri));
		
		if (exactMatch && !results.isEmpty())
			return results;
		
		try {
			Pattern p = Pattern.compile(baseUri);
			updateResourceCache();
			Set<String> keySet = tenantMap.keySet();
			keySet.forEach( key -> {
			    Matcher m = p.matcher(key);
			    if(m.find())
			    		results.add(tenantMap.get(key));
			});
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
		
		logger.debug("uri "+ baseUri + " is matched by resources" + results);
		return results;
	}
	
	public static Set<ScopeRepresentation> getScopeRepresentationSet(String[] scopes){
		Set<ScopeRepresentation> scopeSet = new HashSet<ScopeRepresentation>();
		for (String scope: scopes)         
			scopeSet.add(getScopeRepresentation(scope));
		return scopeSet;
	}
	
	public static ScopeRepresentation getScopeRepresentation(String scope) {
		ScopeRepresentation sr = new ScopeRepresentation();
		sr.setName(scope);
		return sr;
	}
	
    public static String createURI(String basePath, String resourceId) {
		if (basePath.endsWith("/"))
			return basePath+resourceId;
		if (resourceId.equals("*") || resourceId.equals("(.*)"))
			return basePath+resourceId;
		return basePath+"/"+resourceId;
   }

    private JsonNode readPayload(String oauthPayload) {
        try {
            return MAPPER.readTree(oauthPayload);
        } catch (IOException ioe) {
            logger.error("Unable to check required scope from introspection endpoint payload: {}", oauthPayload);
            return null;
        }
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
    
    
}
