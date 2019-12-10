package com.dnastack.ddap.explore.dam.client;

import com.dnastack.ddap.common.config.DamProperties;
import com.dnastack.ddap.common.oauth.ReactiveOAuthClient;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.util.UriTemplate;

import java.net.URI;
import java.util.List;

@Slf4j
public class ReactiveDamOAuthClient extends ReactiveOAuthClient {

    public ReactiveDamOAuthClient(DamProperties damProperties) {
        super(new AuthServerInfo(damProperties.getClientId(), damProperties.getClientSecret(), new DamEndpointResolver(damProperties.getBaseUrl())));
    }

    public URI getAuthorizeUrl(String realm, String state, String scopes, URI redirectUri, List<URI> resources) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri)
                .queryParam("resource", resources.toArray())
                .queryParam("ttl", "1h") // FIXME pass this in
                .build();
    }

    @AllArgsConstructor
    public static class DamEndpointResolver implements OAuthEndpointResolver {
        private final URI baseUrl;

        @Override
        public URI getAuthorizeEndpoint(String realm) {
            return baseUrl.resolve(new UriTemplate("/dam/oidc/authorize").expand(realm));
        }

        @Override
        public URI getTokenEndpoint(String realm) {
            return baseUrl.resolve(new UriTemplate("/dam/oidc/token").expand(realm));
        }

        @Override
        public URI getRevokeEndpoint(String realm) {
            return baseUrl.resolve(new UriTemplate("/dam/oidc/revoke").expand(realm));
        }
    }
}
