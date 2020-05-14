package com.dnastack.ddap.ic.oauth.service;

import com.dnastack.ddap.common.security.TokenExchangePurpose;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.ic.oauth.client.ReactiveIdpOAuthClient;
import com.dnastack.ddap.ic.oauth.client.TokenExchangeException;
import com.dnastack.ddap.ic.oauth.model.TokenResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.net.URI;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.DAM;

@Slf4j
@Component
@ConditionalOnExpression("${idp.enabled:false} and not ${ic.enabled:false}")
public class DamLoginService extends LoginService {

    public DamLoginService(UserTokenCookiePackager cookiePackager, ReactiveIdpOAuthClient oAuthClient) {
        super(cookiePackager, oAuthClient);
    }

    @Override
    public Mono<? extends ResponseEntity<?>> finishLogin(ServerHttpRequest request, String realm, TokenExchangePurpose tokenExchangePurpose, TokenResponse tokenResponse, URI ddapDataBrowserUrl) {
        if (tokenExchangePurpose == TokenExchangePurpose.LOGIN) {
            return Mono.just(assembleTokenResponse(ddapDataBrowserUrl, tokenResponse));
        } else {
            return Mono.error(new TokenExchangeException("Unrecognized purpose in token exchange"));
        }
    }

    @Override
    protected UserTokenCookiePackager.CookieName accessTokenName() {
        return DAM.cookieName(UserTokenCookiePackager.TokenKind.ACCESS);
    }

    @Override
    protected UserTokenCookiePackager.CookieName idTokenName() {
        return DAM.cookieName(UserTokenCookiePackager.TokenKind.IDENTITY);
    }

    @Override
    protected UserTokenCookiePackager.CookieName refreshTokenName() {
        return DAM.cookieName(UserTokenCookiePackager.TokenKind.REFRESH);
    }

}
