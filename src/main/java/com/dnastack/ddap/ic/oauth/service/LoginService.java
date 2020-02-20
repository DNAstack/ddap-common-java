package com.dnastack.ddap.ic.oauth.service;

import com.dnastack.ddap.common.security.TokenExchangePurpose;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.util.http.UriUtil;
import com.dnastack.ddap.ic.common.security.JwtUtil;
import com.dnastack.ddap.ic.oauth.client.ReactiveIdpOAuthClient;
import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Instant;
import java.util.*;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.IC;
import static com.dnastack.ddap.common.security.UserTokenCookiePackager.*;
import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.http.HttpStatus.TEMPORARY_REDIRECT;

@Slf4j
@RequiredArgsConstructor
public abstract class LoginService {

    private static final Integer EXPIRATION_GRACE_PERIOD_IN_SECONDS = 300;

    protected final UserTokenCookiePackager cookiePackager;
    protected final ReactiveIdpOAuthClient oAuthClient;

    public abstract Mono<? extends ResponseEntity<?>> finishLogin(ServerHttpRequest icAccessToken, String realm, TokenExchangePurpose tokenExchangePurpose, TokenResponse tokenResponse, URI ddapDataBrowserUrl);

    public Mono<? extends ResponseEntity<?>> refresh(ServerHttpRequest request, String realm) {
        Map<CookieName, CookieValue> tokens = cookiePackager.extractRequiredTokens(request, Set.of(IC.cookieName(TokenKind.ACCESS), IC.cookieName(TokenKind.REFRESH)));
        CookieValue accessToken = tokens.get(IC.cookieName(TokenKind.ACCESS));
        CookieValue refreshToken = tokens.get(IC.cookieName(TokenKind.REFRESH));

        // Skip refreshing if it is not needed
        if (!isExpiringSoon(accessToken)) {
            return Mono.just(ResponseEntity.noContent().build());
        }
        List<String> scopes = getActiveScopes(accessToken);

        URI cookieDomainPath = UriUtil.selfLinkToApi(request, realm, "identity/token");
        Mono<TokenResponse> refreshAccessTokenMono = oAuthClient.refreshAccessToken(realm, refreshToken.getClearText(), String.join(" ", scopes));

        return refreshAccessTokenMono.map((tokenResponse) -> {
            final ResponseEntity.HeadersBuilder<?> response = ResponseEntity.noContent()
                .location(UriUtil.selfLinkToUi(request, realm, "identity"))
                .header(SET_COOKIE, cookiePackager.packageToken(tokenResponse.getAccessToken(), cookieDomainPath.getHost(), accessTokenName()).toString())
                .header(SET_COOKIE, cookiePackager.packageToken(tokenResponse.getIdToken(), cookieDomainPath.getHost(), idTokenName()).toString());
            if (tokenResponse.getRefreshToken() != null) {
                response.header(SET_COOKIE, cookiePackager.packageToken(tokenResponse.getRefreshToken(), cookieDomainPath.getHost(), refreshTokenName()).toString());
            }

            return response.build();
        });
    }

    private boolean isExpiringSoon(CookieValue accessToken) {
        return JwtUtil.dangerousStopgapExtractSubject(accessToken.getClearText())
            .map((jwt) -> {
                Instant expiresAt = jwt.getExp();
                return Instant.now().plusSeconds(EXPIRATION_GRACE_PERIOD_IN_SECONDS).isAfter(expiresAt);
            })
            .orElse(true);
    }

    private List<String> getActiveScopes(CookieValue accessToken) {
        return JwtUtil.dangerousStopgapExtractSubject(accessToken.getClearText())
            .map(JwtUtil.JwtSubject::getScp)
            .orElse(Collections.emptyList());
    }

    /**
     * Examines the result of an auth-code-for-token exchange with the Identity Concentrator and creates a response
     * which sets the appropriate cookies on the user's client and redirects it to the appropriate part of the UI.
     *
     * @param token the token response from the outbound request we initiated with the Identity Concentrator.
     * @return A response entity that sets the user's token cookies and redirects to the UI. Never null.
     */
    protected ResponseEntity<?> assembleTokenResponse(URI redirectTo, TokenResponse token) {
        Set<String> missingItems = new HashSet<>();
        if (token == null) {
            missingItems.add("token");
        } else {
            if (token.getAccessToken() == null) {
                missingItems.add("access_token");
            }
            if (token.getIdToken() == null) {
                missingItems.add("id_token");
            }
        }

        if (!missingItems.isEmpty()) {
            throw new IllegalArgumentException("Incomplete token response: missing " + missingItems);
        }

        final String publicHost = redirectTo.getHost();
        final ResponseCookie identityToken = cookiePackager.packageToken(token.getIdToken(), publicHost, idTokenName());
        final ResponseCookie accessToken = cookiePackager.packageToken(token.getAccessToken(), publicHost, accessTokenName());
        final ResponseEntity.BodyBuilder builder = ResponseEntity.status(TEMPORARY_REDIRECT)
            .location(redirectTo)
            .header(SET_COOKIE, identityToken.toString())
            .header(SET_COOKIE, accessToken.toString());
        if (token.getRefreshToken() != null) {
            final ResponseCookie refreshTokenCookie = cookiePackager.packageToken(token.getRefreshToken(), publicHost, refreshTokenName());
            builder.header(SET_COOKIE, refreshTokenCookie.toString());
        }

        return builder.build();
    }

    protected abstract CookieName refreshTokenName();

    protected abstract CookieName accessTokenName();

    protected abstract CookieName idTokenName();
}
