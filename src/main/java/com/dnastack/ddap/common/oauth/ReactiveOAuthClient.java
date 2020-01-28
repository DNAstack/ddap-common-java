package com.dnastack.ddap.common.oauth;

import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientResponse;
import reactor.core.publisher.Mono;

import java.net.URI;

public interface ReactiveOAuthClient {
    Mono<TokenResponse> exchangeAuthorizationCodeForTokens(String realm, URI redirectUri, String code);

    // TODO remove after Hydra deployed in all environments
    Mono<TokenResponse> legacyExchangeAuthorizationCodeForTokens(String realm, URI redirectUri, String code);

    Mono<HttpStatus> testAuthorizeEndpoint(URI uri);

    Mono<TokenResponse> refreshAccessToken(String realm, String refreshToken, String scope);

    // TODO remove after Hydra deployed in all environments
    Mono<TokenResponse> legacyRefreshAccessToken(String realm, String refreshToken);

    Mono<ClientResponse> revokeRefreshToken(String realm, String refreshToken);

    // TODO remove after Hydra deployed in all environments
    Mono<ClientResponse> legacyRevokeRefreshToken(String realm, String refreshToken);

    URI getAuthorizeUrl(String realm, String state, String scopes, URI redirectUri);

    URI getLegacyAuthorizeUrl(String realm, String state, String scopes, URI redirectUri);

    Mono<Object> getUserInfo(String realm, String accessToken);
}
