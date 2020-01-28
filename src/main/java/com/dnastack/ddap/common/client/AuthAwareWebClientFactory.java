package com.dnastack.ddap.common.client;

import org.springframework.web.reactive.function.client.WebClient;

public interface AuthAwareWebClientFactory {
    WebClient getWebClient(String realm, String refreshToken, OAuthFilter.Audience audience);
}
