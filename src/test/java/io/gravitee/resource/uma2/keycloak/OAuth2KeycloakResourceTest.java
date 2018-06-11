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

import com.github.tomakehurst.wiremock.junit.WireMockRule;

import io.gravitee.resource.oauth2.api.OAuth2Response;
import io.gravitee.resource.uma2.keycloak.Uma2KeycloakResource;
import io.gravitee.resource.uma2.keycloak.configuration.Uma2KeycloakResourceConfiguration;
import io.vertx.core.Vertx;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.context.ApplicationContext;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.mockito.MockitoAnnotations.initMocks;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2KeycloakResourceTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private Uma2KeycloakResourceConfiguration configuration;

    @InjectMocks
    private Uma2KeycloakResource resource;
    
	private static final String keyCloakconfig = "{\n" + 
			"  \"realm\": \"master\",\n" + 
			"  \"auth-server-url\": \"http://127.0.0.1:8081/auth\",\n" + 
			"  \"ssl-required\": \"external\",\n" + 
			"  \"resource\": \"test\",\n" + 
			"  \"credentials\": {\n" + 
			"    \"secret\": \"2ac7b9f0-24b2-4e72-a4d2-733bc344a15a\"\n" + 
			"  },\n" + 
			"  \"confidential-port\": 0,\n" + 
			"  \"policy-enforcer\": {}\n" + 
			"}";

    @Before
    public void init() {
        initMocks(this);
        Mockito.when(applicationContext.getBean(Vertx.class)).thenReturn(Vertx.vertx());
    }
    
    @Test
    public void shouldAuthorize() throws Exception {
        final CountDownLatch lock = new CountDownLatch(1);
    		
    		String accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPZ2ZOclRIMUZyZlpXNmQ5QzdoMVVIc2JIeDlDTnQ2b2R1REkzMWtFbjZnIn0.eyJqdGkiOiI5ZjA5Mjk1NS0xNDQ4LTQxYjEtOWQyZi1hOTYzYTA4YTc4NTQiLCJleHAiOjE1Mjc0Mjg2MTksIm5iZiI6MCwiaWF0IjoxNTI3NDI1MDE5LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdCIsInN1YiI6Ijg4OWVlOWNiLTgwNjUtNDE0OS1iYmQwLWY1ZGFkZmUwZjQwZSIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJmMTZmODk0ZC03YTFhLTQ3MzAtODM0NC00YmIyMjgyZDUwNTkiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidGVzdCI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJncm91cHMiOlsiL2FudHdlcnBlbiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.QPOJczKmIUQYEqLSoS5ytIYxBVyA8IRCiyehUebZNqqzJonYh1QQyoh9D6wOmP5jnSKkYHiY8dlX6SNMS18g8i-86Mzohc5gYJ51U5HXiKNWKQob9monayUQuuVD2AK11Uo5MIPDp9MFbLgaQGMPfoK3KLluizN8373_kTtt0-jrm5rQEcULmL7RSeArB9zIG8z7L0ZXl0hNJdrmFInnal8uMU0YH5-BPU96XxV6XABTHRnqFB4ZGQgcbyxx9tVUspbrmM4cfKs6x255061ClKFwps0srXCZDEmkyjGfvZvdHrAiaWOOFlgVHHBKaIeZLnlQ9sqdLM4L-kX57iQLbQ";
    		Mockito.when(configuration.getKeycloakConfiguration()).thenReturn(keyCloakconfig);
        resource.doStart();
        
        String audience = "test";
        String[] permissions = {"29dcfb3c-cbe0-42fe-a8d9-04ad4effb62f#read"};
        
        resource.authorizeUma(accessToken, permissions, audience, Auth2Response -> {
        		Assert.assertEquals(true, Auth2Response.isSuccess());
        		lock.countDown();
        });

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }
    
    @Test
    public void shouldNotAuthorize() throws Exception {
        final CountDownLatch lock = new CountDownLatch(1);
    	
    		String accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPZ2ZOclRIMUZyZlpXNmQ5QzdoMVVIc2JIeDlDTnQ2b2R1REkzMWtFbjZnIn0.eyJqdGkiOiI5ZjA5Mjk1NS0xNDQ4LTQxYjEtOWQyZi1hOTYzYTA4YTc4NTQiLCJleHAiOjE1Mjc0Mjg2MTksIm5iZiI6MCwiaWF0IjoxNTI3NDI1MDE5LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdCIsInN1YiI6Ijg4OWVlOWNiLTgwNjUtNDE0OS1iYmQwLWY1ZGFkZmUwZjQwZSIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJmMTZmODk0ZC03YTFhLTQ3MzAtODM0NC00YmIyMjgyZDUwNTkiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidGVzdCI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJncm91cHMiOlsiL2FudHdlcnBlbiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.QPOJczKmIUQYEqLSoS5ytIYxBVyA8IRCiyehUebZNqqzJonYh1QQyoh9D6wOmP5jnSKkYHiY8dlX6SNMS18g8i-86Mzohc5gYJ51U5HXiKNWKQob9monayUQuuVD2AK11Uo5MIPDp9MFbLgaQGMPfoK3KLluizN8373_kTtt0-jrm5rQEcULmL7RSeArB9zIG8z7L0ZXl0hNJdrmFInnal8uMU0YH5-BPU96XxV6XABTHRnqFB4ZGQgcbyxx9tVUspbrmM4cfKs6x255061ClKFwps0srXCZDEmkyjGfvZvdHrAiaWOOFlgVHHBKaIeZLnlQ9sqdLM4L-kX57iQLbQ";
    		Mockito.when(configuration.getKeycloakConfiguration()).thenReturn(keyCloakconfig);
        resource.doStart();
        
        String audience = "test";
        String[] permissions = {"4c36d7f5-ae25-42f5-9a74-aa26ab90b71e#read"};
        
        resource.authorizeUma(accessToken, permissions, audience, Auth2Response -> {
        		Assert.assertEquals(false, Auth2Response.isSuccess());
        		lock.countDown();
        });

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }
    
    @Test
    public void shouldNotAuthorizeInvalidToken() throws Exception {
        final CountDownLatch lock = new CountDownLatch(1);
    	
    		String accessToken = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPZ2ZOclRIMUZyZlpXNmQ5QzdoMVVIc2JIeDlDTnQ2b2R1REkzMWtFbjZnIn0.eyJqdGkiOiJhOTMzYWM2ZS03MjJlLTQ5ZTQtYjQ1Yi1mNjQ5M2RhOTc1NDkiLCJleHAiOjE1Mjc0MjYxODgsIm5iZiI6MCwiaWF0IjoxNTI3NDI2MTI4LCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgwODEvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoidGVzdCIsInN1YiI6Ijg4OWVlOWNiLTgwNjUtNDE0OS1iYmQwLWY1ZGFkZmUwZjQwZSIsInR5cCI6IkJlYXJlciIsImF6cCI6InRlc3QiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiIwMWVhY2QwNi0zMGI0LTQ2NzMtYjk2OC0wM2ZmNTk2MTZmZjIiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsidGVzdCI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiJdfSwibWFzdGVyLXJlYWxtIjp7InJvbGVzIjpbInZpZXctcmVhbG0iLCJ2aWV3LWlkZW50aXR5LXByb3ZpZGVycyIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwiY3JlYXRlLWNsaWVudCIsIm1hbmFnZS11c2VycyIsInF1ZXJ5LXJlYWxtcyIsInZpZXctYXV0aG9yaXphdGlvbiIsInF1ZXJ5LWNsaWVudHMiLCJxdWVyeS11c2VycyIsIm1hbmFnZS1ldmVudHMiLCJtYW5hZ2UtcmVhbG0iLCJ2aWV3LWV2ZW50cyIsInZpZXctdXNlcnMiLCJ2aWV3LWNsaWVudHMiLCJtYW5hZ2UtYXV0aG9yaXphdGlvbiIsIm1hbmFnZS1jbGllbnRzIiwicXVlcnktZ3JvdXBzIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJncm91cHMiOlsiL2FudHdlcnBlbiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhZG1pbiJ9.Z3PaZwl39Aq4aq4slPLPJ7JMiVSIQz8FfC3w9IzQ7cR0wfUj9scEm680AqB_LbI_YawoH4hYI1qQYV6iHuR3PTlBaWFQnUApbMTsAdu8yewJhVPlVYT6vdAZUDOtcRAPm5n6b0DRqOKsejxCfpzVYZkMzaDbcuHRxlChmBqqPkbMUybZ2Ce5dHL8YQyKsst0iwpje-_I6zKsU4v6xUFHjI4DSLfkzs7LxhvH4yT7jiXUfiRKMrnfQ1WCZISxUeCwypweu1DAE-nX4hr97dPUjGIsbJJ1fzZWCtQFXHCtrhsJxYyd2N-HLEnQ4Wue0jLeckr4ruFqIjsUC-mKhofufg";
    	    Mockito.when(configuration.getKeycloakConfiguration()).thenReturn(keyCloakconfig);
        resource.doStart();
        
        String audience = "test";
        String[] permissions = {"4c36d7f5-ae25-42f5-9a74-aa26ab90b71e#read"};
        
        resource.authorizeUma(accessToken, permissions, audience, Auth2Response -> {
        		Assert.assertEquals(false, Auth2Response.isSuccess());
        		lock.countDown();
        });

        Assert.assertEquals(true, lock.await(10000, TimeUnit.MILLISECONDS));
    }

}
