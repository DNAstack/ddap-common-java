package com.dnastack.ddap.ic.account.service;

import com.dnastack.ddap.common.config.ProfileService;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.ic.account.model.IdentityModel;
import com.dnastack.ddap.ic.common.security.JwtUtil;
import com.dnastack.ddap.ic.oauth.client.ReactiveIdpOAuthClient;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PathVariable;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Optional;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.DAM;

@Component
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class DamUserInfoIdentityService implements IdentityService {
    private final ReactiveIdpOAuthClient idpClient;
    private final UserTokenCookiePackager cookiePackager;
    private final ProfileService profileService;

    @Override
    public Mono<IdentityModel> getIdentity(ServerHttpRequest request, @PathVariable String realm) {
        final UserTokenCookiePackager.CookieValue token = cookiePackager.extractRequiredToken(request, DAM.cookieName(UserTokenCookiePackager.TokenKind.ACCESS));

        Mono<Object> userInfoMono = idpClient.getUserInfo(realm, token.getClearText());

        return userInfoMono.map(userInfo -> {
            Optional<JwtUtil.JwtSubject> subject = JwtUtil.dangerousStopgapExtractSubject(token.getClearText());
            return IdentityModel.builder()
                .account(userInfo)
                .scopes(subject.map(JwtUtil.JwtSubject::getScp).orElse(Collections.emptyList()))
                .sandbox(profileService.isSandboxProfileActive())
                .build();
        });
    }
}
