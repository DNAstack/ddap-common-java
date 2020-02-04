package com.dnastack.ddap.common.oauth;

import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import reactor.core.publisher.Mono;

import java.net.URI;

public interface ReactiveOAuthClient {
    Mono<TokenResponse> exchangeAuthorizationCodeForTokens(String realm, URI redirectUri, String code);

    Mono<TokenResponse> refreshAccessToken(String realm, String refreshToken, String scope);

    Mono<ClientResponse> revokeRefreshToken(String realm, String refreshToken);

    URI getAuthorizeUrl(String realm, String state, String scopes, URI redirectUri, String loginHint);

    Mono<Object> getUserInfo(String realm, String accessToken);
}
