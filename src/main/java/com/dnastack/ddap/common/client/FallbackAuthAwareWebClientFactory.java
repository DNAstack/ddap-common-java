package com.dnastack.ddap.common.client;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
@ConditionalOnExpression("not ${idp.enabled:false}")
public class FallbackAuthAwareWebClientFactory implements AuthAwareWebClientFactory {

    @Override
    public WebClient getWebClient(String realm, String refreshToken, OAuthFilter.Audience audience) {
        return WebClientFactory.getWebClient();
    }

}
