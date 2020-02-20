package com.dnastack.ddap.common.oauth;

import com.dnastack.ddap.common.client.WebClientFactory;
import com.dnastack.ddap.common.security.InvalidTokenException;
import com.dnastack.ddap.ic.oauth.client.TokenExchangeException;
import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import lombok.AllArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Base64;
import java.util.Optional;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON;

@AllArgsConstructor
@Slf4j
public class BaseReactiveOAuthClient implements ReactiveOAuthClient {
    private final AuthServerInfo authServerInfo;

    @Value
    public static class AuthServerInfo {
        private String clientId;
        private String clientSecret;
        private OAuthEndpointResolver resolver;
    }

    public interface OAuthEndpointResolver {
        URI getAuthorizeEndpoint(String realm);
        URI getTokenEndpoint(String realm);
        URI getRevokeEndpoint(String realm);
        Optional<URI> getUserInfoEndpoint(String realm);
    }

    @Override
    public Mono<TokenResponse> exchangeAuthorizationCodeForTokens(String realm, URI redirectUri, String code) {
        final URI uri = authServerInfo.getResolver().getTokenEndpoint(realm);

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(uri)
                               .header(AUTHORIZATION, "Basic " + encodeBasicAuth(authServerInfo.getClientId(), authServerInfo.getClientSecret()))
                               .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                               .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                                                  .with("redirect_uri", redirectUri.toString())
                                                  .with("code", code))
                               .exchange()
                               .flatMap(this::extractIdpTokens)
                               .onErrorMap(ex ->  new InvalidTokenException(ex.getMessage()));
    }

    @Override
    public Mono<Object> getUserInfo(String realm, String accessToken) {
        final Optional<URI> foundEndpoint = authServerInfo.getResolver().getUserInfoEndpoint(realm);
        return foundEndpoint.map(uri -> WebClientFactory.getWebClient()
                                                        .get()
                                                        .uri(uri)
                                                        .header(AUTHORIZATION, "Bearer " + accessToken)
                                                        .accept(APPLICATION_JSON)
                                                        .exchange()
                                                        .flatMap(response -> response.bodyToMono(Object.class)))
                            .orElseGet(() -> Mono.error(new UnsupportedOperationException("No user info endpoint specified")));
    }

    private String encodeBasicAuth(String user, String password) {
        return Base64.getEncoder()
                     .encodeToString((user + ":" + password).getBytes());
    }

    @Override
    public Mono<TokenResponse> refreshAccessToken(String realm, String refreshToken, String scope) {
        final URI uri = authServerInfo.getResolver().getTokenEndpoint(realm);

        final BodyInserters.FormInserter<String> params = BodyInserters.fromFormData("refresh_token", refreshToken)
            .with("grant_type", "refresh_token");

        if (scope != null) {
            params.with("scope", scope);
        }

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(uri)
                               .header("Authorization", "Basic " + encodeBasicAuth(authServerInfo.getClientId(), authServerInfo.getClientSecret()))
                               .body(params)
                               .exchange()
                               .flatMap(this::extractIdpTokens)
                               .onErrorMap(ex ->  new InvalidTokenException(ex.getMessage()));
    }

    @Override
    public Mono<ClientResponse> revokeRefreshToken(String realm, String refreshToken) {
        final URI uri = authServerInfo.getResolver().getRevokeEndpoint(realm);

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(uri)
                               .header("Authorization", "Basic " + encodeBasicAuth(authServerInfo.getClientId(), authServerInfo.getClientSecret()))
                               .body(BodyInserters.fromFormData("refresh_token", refreshToken))
                               .exchange();
    }

    private Mono<TokenResponse> extractIdpTokens(ClientResponse idpTokenResponse) {
        if (idpTokenResponse.statusCode().is2xxSuccessful() && contentTypeIsApplicationJson(idpTokenResponse)) {
            return idpTokenResponse.bodyToMono(TokenResponse.class);
        } else {
            return idpTokenResponse.bodyToMono(String.class)
                                   .flatMap(errorBody -> Mono.error(new TokenExchangeException(errorBody)));
        }
    }

    private static boolean contentTypeIsApplicationJson(ClientResponse response) {
        return response.headers()
                       .contentType()
                       .filter(mediaType -> mediaType.isCompatibleWith(APPLICATION_JSON))
                       .isPresent();
    }

    protected UriBuilder getAuthorizedUriBuilder(String realm, String state, String scopes, URI redirectUri, String loginHint) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri, authServerInfo.getResolver(), loginHint);
    }

    private UriBuilder getAuthorizedUriBuilder(String realm, String state, String scopes, URI redirectUri, OAuthEndpointResolver resolver, String loginHint) {
        final UriComponentsBuilder builder = UriComponentsBuilder.fromUri(resolver.getAuthorizeEndpoint(realm))
                                                                 .queryParam("response_type", "code")
                                                                 .queryParam("client_id", authServerInfo.getClientId())
                                                                 .queryParam("redirect_uri", redirectUri)
                                                                 .queryParam("state", state);
        if (scopes != null) {
            builder.queryParam("scope", scopes);
        }
        if (loginHint != null) {
            builder.queryParam("login_hint", loginHint);
        }

        return builder;
    }

    @Override
    public URI getAuthorizeUrl(String realm, String state, String scopes, URI redirectUri, String loginHint) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri, loginHint)
            .build();
    }
}
