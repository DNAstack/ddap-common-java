package com.dnastack.ddap.ic.oauth.client;

import com.dnastack.ddap.common.oauth.BaseReactiveOAuthClient;
import com.dnastack.ddap.ic.common.config.IdpProperties;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriTemplate;

import java.net.URI;
import java.util.Optional;

@Slf4j
@Component
@ConditionalOnExpression("${idp.enabled:false}")
public class ReactiveIdpOAuthClient extends BaseReactiveOAuthClient {

    public ReactiveIdpOAuthClient(IdpProperties idpProperties) {
        super(new AuthServerInfo(idpProperties.getClientId(), idpProperties.getClientSecret(), new IcEndpointResolver(idpProperties)));
    }

    public URI getAuthorizeUrl(String realm, String state, String scopes, URI redirectUri, String loginHint) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri, loginHint)
                .queryParam("realm", realm)
                .build();
    }

    @AllArgsConstructor
    public static class IcEndpointResolver implements OAuthEndpointResolver {
        private final IdpProperties idpProperties;

        @Override
        public URI getAuthorizeEndpoint(String realm) {
            return new UriTemplate(idpProperties.getAuthorizeUrl()).expand(realm);
        }

        @Override
        public URI getTokenEndpoint(String realm) {
            return new UriTemplate(idpProperties.getTokenUrl()).expand(realm);
        }

        @Override
        public URI getRevokeEndpoint(String realm) {
            return new UriTemplate(idpProperties.getRevokeUrl()).expand(realm);
        }

        @Override
        public Optional<URI> getUserInfoEndpoint(String realm) {
            return Optional.ofNullable(idpProperties.getUserInfoUrl())
                           .map(uri -> new UriTemplate(uri).expand(realm));
        }
    }
}
