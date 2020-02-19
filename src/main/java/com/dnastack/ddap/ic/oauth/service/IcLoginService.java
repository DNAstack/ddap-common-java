package com.dnastack.ddap.ic.oauth.service;

import com.dnastack.ddap.common.security.TokenExchangePurpose;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.ic.oauth.client.ReactiveIdpOAuthClient;
import com.dnastack.ddap.ic.oauth.client.TokenExchangeException;
import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import com.dnastack.ddap.ic.service.AccountLinkingService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.IC;

@Component
@ConditionalOnExpression("${ic.enabled:false}")
public class IcLoginService extends LoginService {

    private final AccountLinkingService accountLinkingService;

    public IcLoginService(UserTokenCookiePackager cookiePackager,
                          ReactiveIdpOAuthClient oAuthClient,
                          AccountLinkingService accountLinkingService) {
        super(cookiePackager, oAuthClient);
        this.accountLinkingService = accountLinkingService;
    }

    @Override
    public Mono<? extends ResponseEntity<?>> finishLogin(ServerHttpRequest request, String realm, TokenExchangePurpose tokenExchangePurpose, TokenResponse tokenResponse, URI ddapDataBrowserUrl) {
        if (tokenExchangePurpose == TokenExchangePurpose.LOGIN) {
            return Mono.just(assembleTokenResponse(ddapDataBrowserUrl, tokenResponse));
        } else if (tokenExchangePurpose == TokenExchangePurpose.LINK) {
            final UserTokenCookiePackager.CookieValue accessToken = cookiePackager.extractRequiredToken(request, IC.cookieName(UserTokenCookiePackager.TokenKind.ACCESS));
            return accountLinkingService.finishAccountLinking(tokenResponse.getAccessToken(), accessToken.getClearText(), realm)
                .map(success -> ResponseEntity.status(307).location(ddapDataBrowserUrl).build());
        } else {
            return Mono.error(new TokenExchangeException("Unrecognized purpose in token exchange"));
        }
    }

    @Override
    protected UserTokenCookiePackager.CookieName accessTokenName() {
        return IC.cookieName(UserTokenCookiePackager.TokenKind.ACCESS);
    }

    @Override
    protected UserTokenCookiePackager.CookieName idTokenName() {
        return IC.cookieName(UserTokenCookiePackager.TokenKind.IDENTITY);
    }

    @Override
    protected UserTokenCookiePackager.CookieName refreshTokenName() {
        return IC.cookieName(UserTokenCookiePackager.TokenKind.REFRESH);
    }

}
