package com.dnastack.ddap.ic.account.controller;

import com.dnastack.ddap.common.config.ProfileService;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieValue;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import com.dnastack.ddap.ic.account.client.ReactiveIcAccountClient;
import com.dnastack.ddap.ic.account.model.IdentityModel;
import com.dnastack.ddap.ic.account.service.IdentityService;
import com.dnastack.ddap.ic.common.security.JwtUtil;
import com.dnastack.ddap.ic.oauth.client.ReactiveIdpOAuthClient;
import ic.v1.IcService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.DAM;

@Slf4j
@RestController
@RequestMapping("/api/v1alpha/realm/{realm}/identity")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
@ConditionalOnExpression("${ic.enabled:false} or ${idp.enabled:false}")
public class IcIdentityController {
    private final IdentityService identityService;

    @GetMapping
    public Mono<? extends ResponseEntity<?>> getIdentity(ServerHttpRequest request, @PathVariable String realm) {
        final Mono<IdentityModel> retVal = identityService.getIdentity(request, realm);
        return retVal.flatMap(account -> Mono.just(ResponseEntity.ok().body(account)));
    }

}
