package com.dnastack.ddap.ic.account.service;

import com.dnastack.ddap.common.config.ProfileService;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.ic.account.client.ReactiveIcAccountClient;
import com.dnastack.ddap.ic.account.model.IdentityModel;
import com.dnastack.ddap.ic.common.security.JwtUtil;
import ic.v1.IcService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PathVariable;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Optional;

@Component
@ConditionalOnExpression("${ic.enabled:false}")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class IcIdentityService implements IdentityService {
    private final ReactiveIcAccountClient idpClient;
    private final UserTokenCookiePackager cookiePackager;
    private final ProfileService profileService;

    @Override
    public Mono<IdentityModel> getIdentity(ServerHttpRequest request, @PathVariable String realm) {
        final UserTokenCookiePackager.CookieValue icToken = cookiePackager.extractRequiredToken(request, UserTokenCookiePackager.BasicServices.IC.cookieName(UserTokenCookiePackager.TokenKind.ACCESS));
        final UserTokenCookiePackager.CookieValue refreshToken = cookiePackager.extractTokenIgnoringInvalid(request, UserTokenCookiePackager.BasicServices.IC.cookieName(UserTokenCookiePackager.TokenKind.REFRESH)).orElse(null);

        Mono<IcService.AccountResponse> accountMono = idpClient.getAccounts(realm, icToken, refreshToken);

        return accountMono.map(account -> {
            Optional<JwtUtil.JwtSubject> subject = JwtUtil.dangerousStopgapExtractSubject(icToken.getClearText());
            return IdentityModel.builder()
                .account(account.getAccount())
                .scopes(subject.map(JwtUtil.JwtSubject::getScp).orElse(Collections.emptyList()))
                .sandbox(profileService.isSandboxProfileActive())
                .build();
        });
    }
}
