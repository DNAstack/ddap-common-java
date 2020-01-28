package com.dnastack.ddap.common.client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
@ConditionalOnExpression("${idp.enabled:false}")
public class IdpAuthAwareWebClientFactory implements AuthAwareWebClientFactory {

    private OAuthFilter oAuthFilter;

    public IdpAuthAwareWebClientFactory(OAuthFilter oAuthFilter) {
        this.oAuthFilter = oAuthFilter;
    }

    @Override
    public WebClient getWebClient(String realm, String refreshToken, OAuthFilter.Audience audience) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return WebClientFactory.getWebClient();
        }
        return WebClientFactory.getWebClientBuilder()
                .filter(oAuthFilter.refreshAccessTokenFilter(realm, refreshToken, audience))
                .build();
    }

}
