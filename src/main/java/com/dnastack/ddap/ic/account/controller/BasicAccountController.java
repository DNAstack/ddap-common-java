package com.dnastack.ddap.ic.account.controller;

import com.dnastack.ddap.common.config.ProfileService;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieValue;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import com.dnastack.ddap.ic.account.client.ReactiveIcAccountClient;
import com.dnastack.ddap.ic.account.model.IdentityModel;
import com.dnastack.ddap.ic.common.security.JwtUtil;
import ic.v1.IcService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/v1alpha/realm/{realm}/identity")
public class BasicAccountController {

    private ReactiveIcAccountClient idpClient;
    private UserTokenCookiePackager cookiePackager;
    private ProfileService profileService;

    @Autowired
    public BasicAccountController(ReactiveIcAccountClient idpClient,
                                  UserTokenCookiePackager cookiePackager,
                                  ProfileService profileService) {
        this.idpClient = idpClient;
        this.cookiePackager = cookiePackager;
        this.profileService = profileService;
    }

    @GetMapping
    public Mono<? extends ResponseEntity<?>> getIdentity(ServerHttpRequest request, @PathVariable String realm) {
        final CookieValue icToken = cookiePackager.extractRequiredToken(request, BasicServices.IC.cookieName(TokenKind.ACCESS));
        final CookieValue refreshToken = cookiePackager.extractTokenIgnoringInvalid(request, BasicServices.IC.cookieName(TokenKind.REFRESH)).orElse(null);

        Mono<IcService.AccountResponse> accountMono = idpClient.getAccounts(realm, icToken, refreshToken);

        return accountMono.map(account -> {
            Optional<JwtUtil.JwtSubject> subject = JwtUtil.dangerousStopgapExtractSubject(icToken.getClearText());
            return IdentityModel.builder()
                    .account(account.getAccount())
                    .scopes(subject.get().getScope())
                    .sandbox(profileService.isSandboxProfileActive())
                    .build();
        }).flatMap(account -> Mono.just(ResponseEntity.ok().body(account)));
    }

}
