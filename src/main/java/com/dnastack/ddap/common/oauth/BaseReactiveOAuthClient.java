package com.dnastack.ddap.common.oauth;

import com.dnastack.ddap.common.client.WebClientFactory;
import com.dnastack.ddap.common.security.InvalidTokenException;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.ic.oauth.client.TokenExchangeException;
import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriTemplate;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
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
        private OAuthEndpointResolver legacyResolver;
    }

    public interface OAuthEndpointResolver {
        URI getAuthorizeEndpoint(String realm);
        URI getTokenEndpoint(String realm);
        URI getRevokeEndpoint(String realm);
        Optional<URI> getUserInfoEndpoint(String realm);
    }

    @Override
    public Mono<TokenResponse> exchangeAuthorizationCodeForTokens(String realm, URI redirectUri, String code) {
        return hydraAuthorizationCodeForTokens(realm, redirectUri, code)
                .onErrorResume(ex -> {
                    log.info("Error exchanging authorization code at hydra endpoint. Falling back to legacy endpoint: {}", ex.getMessage());
                    return legacyExchangeAuthorizationCodeForTokens(realm, redirectUri, code);
                });
    }

    @Override
    public Mono<Object> getUserInfo(String realm, String accessToken) {
        return getHydraUserInfo(realm, accessToken)
                .onErrorResume(ex -> {
                    log.info("Error getting user info at hydra endpoint. Falling back to legacy endpoint: {}", ex.getMessage());
                    return getLegacyUserInfo(realm, accessToken);
                });
    }

    private Mono<Object> getLegacyUserInfo(String realm, String accessToken) {
        final Optional<URI> foundEndpoint = authServerInfo.getLegacyResolver().getUserInfoEndpoint(realm);
        return foundEndpoint.map(uri -> WebClientFactory.getWebClient()
                                                        .get()
                                                        .uri(uri)
                                                        .header(AUTHORIZATION, "Bearer " + accessToken)
                                                        .accept(APPLICATION_JSON)
                                                        .exchange()
                                                        .flatMap(response -> response.bodyToMono(Object.class)))
                            .orElseGet(() -> Mono.error(new UnsupportedOperationException("No legacy user info endpoint specified")));
    }

    private Mono<Object> getHydraUserInfo(String realm, String accessToken) {
        final Optional<URI> foundEndpoint = authServerInfo.getResolver().getUserInfoEndpoint(realm);
        return foundEndpoint.map(uri -> WebClientFactory.getWebClient()
                                                        .get()
                                                        .uri(uri)
                                                        .header(AUTHORIZATION, "Bearer " + accessToken)
                                                        .accept(APPLICATION_JSON)
                                                        .exchange()
                                                        .flatMap(response -> response.bodyToMono(Object.class)))
                            .orElseGet(() -> Mono.error(new UnsupportedOperationException("No hydra user info endpoint specified")));
    }

    private Mono<TokenResponse> hydraAuthorizationCodeForTokens(String realm, URI redirectUri, String code) {
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

    // TODO remove after Hydra deployed in all environments
    @Override
    public Mono<TokenResponse> legacyExchangeAuthorizationCodeForTokens(String realm, URI redirectUri, String code) {
        final UriTemplate template = new UriTemplate("{tokenEndpoint}" +
                                                             "?grant_type=authorization_code" +
                                                             "&code={code}" +
                                                             "&redirect_uri={redirectUri}" +
                                                             "&clientId={clientId}" +
                                                             "&clientSecret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("tokenEndpoint", authServerInfo.getLegacyResolver().getTokenEndpoint(realm));
        variables.put("code", code);
        variables.put("redirectUri", redirectUri);
        variables.put("clientId", authServerInfo.getClientId());
        variables.put("clientSecret", authServerInfo.getClientSecret());

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(template.expand(variables))
                               .exchange()
                               .flatMap(this::extractIdpTokens)
                               .onErrorMap(ex ->  new InvalidTokenException(ex.getMessage()));
    }

    private String encodeBasicAuth(String user, String password) {
        return Base64.getEncoder()
                     .encodeToString((user + ":" + password).getBytes());
    }

    @Override
    public Mono<HttpStatus> testAuthorizeEndpoint(URI uri) {
        return WebClientFactory.getWebClient()
                               .get()
                               .uri(uri)
                               .exchange()
                               .map(ClientResponse::statusCode);
    }

    @Override
    public Mono<TokenResponse> refreshAccessToken(String realm, String refreshToken, String scope) {
        return hydraRefreshAccessToken(realm, refreshToken, scope)
                .onErrorResume(ex -> {
                    log.info("Error refreshing token via hydra endpoint. Falling back to legacy endpoint: {}", ex.getMessage());
                    return legacyRefreshAccessToken(realm, refreshToken);
                });
    }

    private Mono<TokenResponse> hydraRefreshAccessToken(String realm, String refreshToken, String scope) {
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

    // TODO remove after Hydra deployed in all environments
    @Override
    public Mono<TokenResponse> legacyRefreshAccessToken(String realm, String refreshToken) {
        final UriTemplate template = new UriTemplate("{tokenEndpoint}" +
                                                             "?grant_type=refresh_token" +
                                                             "&refresh_token={refreshToken}" +
                                                             "&clientId={clientId}" +
                                                             "&clientSecret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("tokenEndpoint", authServerInfo.getLegacyResolver().getTokenEndpoint(realm));
        variables.put("refreshToken", refreshToken);
        variables.put("clientId", authServerInfo.getClientId());
        variables.put("clientSecret", authServerInfo.getClientSecret());

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(template.expand(variables))
                               .exchange()
                               .flatMap(this::extractIdpTokens)
                               .onErrorMap(ex ->  new InvalidTokenException(ex.getMessage()));
    }

    @Override
    public Mono<ClientResponse> revokeRefreshToken(String realm, String refreshToken) {
        return hydraRevokeAccessToken(realm, refreshToken)
                .onErrorResume(ex -> {
                    log.info("Error revoking token at hydra endpoint. Falling back to legacy endpoint: {}", ex.getMessage());
                    return legacyRevokeRefreshToken(realm, refreshToken);
                });
    }

    private Mono<ClientResponse> hydraRevokeAccessToken(String realm, String refreshToken) {
        final URI uri = authServerInfo.getResolver().getRevokeEndpoint(realm);

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(uri)
                               .header("Authorization", "Basic " + encodeBasicAuth(authServerInfo.getClientId(), authServerInfo.getClientSecret()))
                               .body(BodyInserters.fromFormData("refresh_token", refreshToken))
                               .exchange();
    }

    // TODO remove after Hydra deployed in all environments
    @Override
    public Mono<ClientResponse> legacyRevokeRefreshToken(String realm, String refreshToken) {
        final UriTemplate template = new UriTemplate("{revokeEndpoint}" +
                                                             "?token={refreshToken}" +
                                                             "&clientId={clientId}" +
                                                             "&clientSecret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("revokeEndpoint", authServerInfo.getResolver().getRevokeEndpoint(realm));
        variables.put("realm", realm);
        variables.put("refreshToken", refreshToken);
        variables.put("clientId", authServerInfo.getClientId());
        variables.put("clientSecret", authServerInfo.getClientSecret());

        return WebClientFactory.getWebClient()
                               .post()
                               .uri(template.expand(variables))
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

    protected UriBuilder getAuthorizedUriBuilder(String realm, String state, String scopes, URI redirectUri) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri, authServerInfo.getResolver());
    }

    protected UriBuilder getLegacyAuthorizedUriBuilder(String realm, String state, String scopes, URI redirectUri) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri, authServerInfo.getLegacyResolver());
    }

    private UriBuilder getAuthorizedUriBuilder(String realm, String state, String scopes, URI redirectUri, OAuthEndpointResolver resolver) {
        final UriComponentsBuilder builder = UriComponentsBuilder.fromUri(resolver.getAuthorizeEndpoint(realm))
                                                                 .queryParam("response_type", "code")
                                                                 .queryParam("client_id", authServerInfo.getClientId())
                                                                 .queryParam("redirect_uri", redirectUri)
                                                                 .queryParam("state", state);
        if (scopes != null) {
            builder.queryParam("scope", scopes);
        }

        return builder;
    }

    @Override
    public URI getAuthorizeUrl(String realm, String state, String scopes, URI redirectUri) {
        return getAuthorizedUriBuilder(realm, state, scopes, redirectUri).build();
    }

    @Override
    public URI getLegacyAuthorizeUrl(String realm, String state, String scopes, URI redirectUri) {
        return getLegacyAuthorizedUriBuilder(realm, state, scopes, redirectUri)
                .build();
    }
}
