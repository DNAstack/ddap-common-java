package com.dnastack.ddap.ic.oauth.controller;

import com.dnastack.ddap.common.security.OAuthStateHandler;
import com.dnastack.ddap.common.security.TokenExchangePurpose;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.util.http.UriUtil;
import com.dnastack.ddap.ic.oauth.client.ReactiveIcOAuthClient;
import com.dnastack.ddap.ic.oauth.client.TokenExchangeException;
import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import com.dnastack.ddap.ic.service.AccountLinkingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static com.dnastack.ddap.common.OAuthConstants.DEFAULT_SCOPES;
import static com.dnastack.ddap.common.util.http.XForwardUtil.getExternalPath;
import static java.lang.String.format;
import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.http.HttpStatus.TEMPORARY_REDIRECT;

@Slf4j
@RestController
public class IcOAuthFlowController {

    private ReactiveIcOAuthClient oAuthClient;
    private UserTokenCookiePackager cookiePackager;
    private OAuthStateHandler stateHandler;
    private AccountLinkingService accountLinkingService;

    @Autowired
    public IcOAuthFlowController(ReactiveIcOAuthClient oAuthClient,
                                 UserTokenCookiePackager cookiePackager,
                                 OAuthStateHandler stateHandler,
                                 AccountLinkingService accountLinkingService) {
        this.oAuthClient = oAuthClient;
        this.cookiePackager = cookiePackager;
        this.stateHandler = stateHandler;
        this.accountLinkingService = accountLinkingService;
    }

    /**
     * Returns the absolute URL that points to the {@link #apiLogin} controller method.
     *
     * @param request the current request (required for determining this service's hostname).
     * @return Absolute URL of the URL an OAuth login flow should redirect to upon completion.
     */
    private static URI rootLoginRedirectUrl(ServerHttpRequest request) {
        return UriUtil.selfLinkToApi(request, "identity/loggedIn");
    }

    @GetMapping("/api/v1alpha/realm/{realm}/identity/logout")
    public Mono<? extends ResponseEntity<?>> invalidateTokens(ServerHttpRequest request, @PathVariable String realm) {
        Optional<UserTokenCookiePackager.CookieValue> foundRefreshToken = cookiePackager.extractToken(request, UserTokenCookiePackager.CookieKind.REFRESH);

        URI cookieDomainPath = UriUtil.selfLinkToApi(request, realm, "identity/token");
        ResponseEntity<Void> response = ResponseEntity.noContent()
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.DAM).toString())
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.IC).toString())
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.OAUTH_STATE).toString())
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.REFRESH).toString())
                                                      .build();

        return foundRefreshToken.map(refreshToken -> oAuthClient.revokeRefreshToken(realm, refreshToken.getClearText())
                                                                .thenReturn(response)
                                                                .onErrorReturn(response))
                                .orElseGet(() -> Mono.just(response));
    }

    @GetMapping("/api/v1alpha/realm/{realm}/identity/login")
    public Mono<? extends ResponseEntity<?>> apiLogin(ServerHttpRequest request,
                                                      @PathVariable String realm,
                                                      @RequestParam(required = false) URI redirectUri,
                                                      @RequestParam(defaultValue = DEFAULT_SCOPES) String scope,
                                                      @RequestParam(required = false) String loginHint) {

        final String state = stateHandler.generateLoginState(redirectUri, realm);

        final URI postLoginTokenEndpoint = UriUtil.selfLinkToApi(request, "identity/loggedIn");
        final URI loginUri = oAuthClient.getAuthorizeUrl(realm, state, scope, postLoginTokenEndpoint, loginHint);
        return oAuthClient.testAuthorizeEndpoint(loginUri)
                   .map(status -> {
                       // For now try the legacy login URI on client error
                       if (status.is4xxClientError()) {
                           log.info("Authorize endpoint returned [{}] status: Falling back to legacy authorize endpoint", status);
                           final URI legacyAuthorizeUrl = oAuthClient.getLegacyAuthorizeUrl(realm, state, scope, postLoginTokenEndpoint, loginHint);
                           return doAuthorizeRedirect(request, realm, state, legacyAuthorizeUrl);
                       } else {
                           return doAuthorizeRedirect(request, realm, state, loginUri);
                       }
                   });
    }

    private ResponseEntity<?> doAuthorizeRedirect(ServerHttpRequest request, @PathVariable String realm, String state, URI loginUri) {
        log.debug("Redirecting to IdP login chooser page {}", loginUri);

        final URI cookieDomainPath = UriUtil.selfLinkToApi(request, realm, "identity/token");
        return ResponseEntity.status(TEMPORARY_REDIRECT)
                             .location(loginUri)
                             .header(SET_COOKIE, cookiePackager.packageToken(state, cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.OAUTH_STATE).toString())
                             .build();
    }

    @GetMapping("/api/v1alpha/realm/{realm}/identity/refresh")
    public Mono<? extends ResponseEntity<?>> refresh(ServerHttpRequest request, @PathVariable String realm) {
        UserTokenCookiePackager.CookieValue refreshToken = cookiePackager.extractRequiredToken(request, UserTokenCookiePackager.CookieKind.REFRESH);

        URI cookieDomainPath = UriUtil.selfLinkToApi(request, realm, "identity/token");
        Mono<TokenResponse> refreshAccessTokenMono = oAuthClient.refreshAccessToken(realm, refreshToken.getClearText(), null);

        return refreshAccessTokenMono.map((tokenResponse) -> {
            final ResponseEntity.HeadersBuilder<?> response =
                    ResponseEntity.noContent()
                                  .location(UriUtil.selfLinkToUi(request, realm, "identity"))
                                  .header(SET_COOKIE, cookiePackager.packageToken(tokenResponse.getAccessToken(), cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.IC).toString())
                                  .header(SET_COOKIE, cookiePackager.packageToken(tokenResponse.getIdToken(), cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.DAM).toString());
            if (tokenResponse.getRefreshToken() != null) {
                response.header(SET_COOKIE, cookiePackager.packageToken(tokenResponse.getRefreshToken(), cookieDomainPath.getHost(), UserTokenCookiePackager.CookieKind.REFRESH).toString());
            }

            return response.build();
        });
    }

    /**
     * OAuth 2 token exchange endpoint for DDAP, which acts as an OAuth 2 client to the Identity Concentrator.
     * <p>
     * This method's purpose is to handle the two HTTP exchanges involved:
     * <ol>
     * <li>the inbound request from the client (usually initiated by a redirect following successful authentication
     * with Identity Concentrator)</li>
     * <li>the outbound request to the Identity Concentrator, to exchange the code for the auth tokens</li>
     * </ol>
     * </p>
     *
     * @return a redirect to the main UI along with some set-cookie headers that store the user's authentication
     * info for subsequent requests.
     */
    @GetMapping("/api/v1alpha/identity/loggedIn")
    public Mono<? extends ResponseEntity<?>> handleTokenRequest(ServerHttpRequest request,
                                                                @RequestParam String code,
                                                                @RequestParam("state") String stateParam,
                                                                @CookieValue("oauth_state") String stateFromCookie) {
        final OAuthStateHandler.ValidatedState validatedState = stateHandler.parseAndVerify(stateParam, stateFromCookie);
        final String realm = validatedState.getRealm();
        final TokenExchangePurpose tokenExchangePurpose = validatedState.getTokenExchangePurpose();
        return oAuthClient.exchangeAuthorizationCodeForTokens(realm, rootLoginRedirectUrl(request), code)
                          .flatMap(tokenResponse -> {
                              Optional<URI> customDestination = validatedState.getDestinationAfterLogin()
                                                                              .map(possiblyRelativeUrl -> UriUtil.selfLinkToUi(request, realm, "").resolve(possiblyRelativeUrl));
                              if (tokenExchangePurpose == TokenExchangePurpose.LOGIN) {
                                  final URI ddapDataBrowserUrl = customDestination.orElseGet(() -> UriUtil.selfLinkToUi(request, realm, ""));
                                  return Mono.just(assembleTokenResponse(ddapDataBrowserUrl, tokenResponse));
                              } else if (tokenExchangePurpose == TokenExchangePurpose.LINK) {
                                  return accountLinkingService.finishAccountLinking(
                                          tokenResponse.getAccessToken(), request.getCookies().getFirst("ic_token").getValue(), realm, null
                                  ).map(success -> ResponseEntity.status(307).location(UriUtil.selfLinkToUi(request, realm, "identity")).build());
                              } else {
                                  return Mono.error(new TokenExchangeException("Unrecognized purpose in token exchange"));
                              }
                          })
                          .doOnError(exception -> log.info("Failed to negotiate token", exception));
    }

    /**
     * Examines the result of an auth-code-for-token exchange with the Identity Concentrator and creates a response
     * which sets the appropriate cookies on the user's client and redirects it to the appropriate part of the UI.
     *
     * @param token the token response from the outbound request we initiated with the Identity Concentrator.
     * @return A response entity that sets the user's token cookies and redirects to the UI. Never null.
     */
    private ResponseEntity<?> assembleTokenResponse(URI redirectTo, TokenResponse token) {
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
        } else {
            final String publicHost = redirectTo.getHost();
            final ResponseCookie damTokenCookie = cookiePackager.packageToken(token.getIdToken(), publicHost, UserTokenCookiePackager.CookieKind.DAM);
            final ResponseCookie icTokenCookie = cookiePackager.packageToken(token.getAccessToken(), publicHost, UserTokenCookiePackager.CookieKind.IC);
            final ResponseEntity.BodyBuilder builder = ResponseEntity.status(TEMPORARY_REDIRECT)
                                                                     .location(redirectTo)
                                                                     .header(SET_COOKIE, damTokenCookie.toString())
                                                                     .header(SET_COOKIE, icTokenCookie.toString());
            if (token.getRefreshToken() != null) {
                final ResponseCookie refreshTokenCookie = cookiePackager.packageToken(token.getRefreshToken(), publicHost, UserTokenCookiePackager.CookieKind.REFRESH);
                builder.header(SET_COOKIE, refreshTokenCookie.toString());
            }

            return builder.build();
        }
    }

}
