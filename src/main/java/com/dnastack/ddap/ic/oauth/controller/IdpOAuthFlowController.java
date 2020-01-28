package com.dnastack.ddap.ic.oauth.controller;

import com.dnastack.ddap.common.security.OAuthStateHandler;
import com.dnastack.ddap.common.security.TokenExchangePurpose;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import com.dnastack.ddap.common.util.http.UriUtil;
import com.dnastack.ddap.ic.oauth.client.ReactiveIdpOAuthClient;
import com.dnastack.ddap.ic.oauth.service.LoginService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Optional;

import static com.dnastack.ddap.common.OAuthConstants.DEFAULT_SCOPES;
import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.IC;
import static org.springframework.http.HttpHeaders.SET_COOKIE;
import static org.springframework.http.HttpStatus.TEMPORARY_REDIRECT;

@Slf4j
@RestController
@ConditionalOnExpression("${idp.enabled:false}")
public class IdpOAuthFlowController {

    private final ReactiveIdpOAuthClient oAuthClient;
    private final OAuthStateHandler stateHandler;
    private final LoginService loginService;
    private final UserTokenCookiePackager cookiePackager;

    @Autowired
    public IdpOAuthFlowController(ReactiveIdpOAuthClient oAuthClient,
                                  UserTokenCookiePackager cookiePackager,
                                  OAuthStateHandler stateHandler,
                                  LoginService loginService) {
        this.oAuthClient = oAuthClient;
        this.cookiePackager = cookiePackager;
        this.stateHandler = stateHandler;
        this.loginService = loginService;
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
        final Optional<UserTokenCookiePackager.CookieValue> foundRefreshToken = cookiePackager.extractTokenIgnoringInvalid(request, IC.cookieName(TokenKind.REFRESH));

        URI cookieDomainPath = UriUtil.selfLinkToApi(request, realm, "identity/token");
        ResponseEntity<Void> response = ResponseEntity.noContent()
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), IC.cookieName(TokenKind.ACCESS)).toString())
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), IC.cookieName(TokenKind.IDENTITY)).toString())
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), IC.cookieName(TokenKind.OAUTH_STATE)).toString())
                                                      .header(SET_COOKIE, cookiePackager.clearToken(cookieDomainPath.getHost(), IC.cookieName(TokenKind.REFRESH)).toString())
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
                             .header(SET_COOKIE, cookiePackager.packageToken(state, cookieDomainPath.getHost(), IC.cookieName(TokenKind.OAUTH_STATE)).toString())
                             .build();
    }

    @GetMapping("/api/v1alpha/realm/{realm}/identity/refresh")
    public Mono<? extends ResponseEntity<?>> refresh(ServerHttpRequest request, @PathVariable String realm) {
        return loginService.refresh(request, realm);
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
                                                                @RequestParam String code) {
        final UserTokenCookiePackager.CookieName cookieName = IC.cookieName(TokenKind.OAUTH_STATE);
        final OAuthStateHandler.ValidatedState validatedState = stateHandler.parseAndVerify(request, cookieName);
        final String realm = validatedState.getRealm();
        final TokenExchangePurpose tokenExchangePurpose = validatedState.getTokenExchangePurpose();
        return oAuthClient.exchangeAuthorizationCodeForTokens(realm, rootLoginRedirectUrl(request), code)
                          .flatMap(tokenResponse -> {
                              Optional<URI> customDestination = validatedState.getDestinationAfterLogin()
                                                                              .map(possiblyRelativeUrl -> UriUtil.selfLinkToUi(request, realm, "").resolve(possiblyRelativeUrl));
                              final URI ddapDataBrowserUrl = customDestination.orElseGet(() -> UriUtil.selfLinkToUi(request, realm, ""));
                              return loginService.finishLogin(request, realm, tokenExchangePurpose, tokenResponse, ddapDataBrowserUrl);
                          })
                          .doOnError(exception -> log.info("Failed to negotiate token", exception));
    }

}
