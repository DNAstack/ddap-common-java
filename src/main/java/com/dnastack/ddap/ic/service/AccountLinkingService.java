package com.dnastack.ddap.ic.service;

import com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieName;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import com.dnastack.ddap.ic.account.client.ReactiveIcAccountClient;
import com.dnastack.ddap.ic.common.config.IcProperties;
import com.dnastack.ddap.ic.common.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@ConditionalOnExpression("${ic.enabled:false}")
public class AccountLinkingService {

    private ReactiveIcAccountClient accountClient;

    @Autowired
    public AccountLinkingService(ReactiveIcAccountClient accountClient) {
        this.accountClient = accountClient;
    }

    public Mono<String> unlinkAccount(String realm, Map<CookieName, String> tokens, String subjectName) {
        String accountId = JwtUtil.dangerousStopgapExtractSubject(tokens.get(BasicServices.IC
                                                                                     .cookieName(TokenKind.ACCESS)))
                                  .map(JwtUtil.JwtSubject::getSub)
                                  .orElse(null);

        return accountClient.unlinkAccount(realm,
                                           accountId,
                                           tokens.get(BasicServices.IC.cookieName(TokenKind.ACCESS)), tokens.get(BasicServices.DAM.cookieName(TokenKind.REFRESH)),
                                           subjectName);
    }

    public Mono<String> finishAccountLinking(String newAccountLinkToken,
                                             String baseAccountLinkToken,
                                             String realm,
                                             String refreshToken) {
        String newAccountId = JwtUtil.dangerousStopgapExtractSubject(newAccountLinkToken).map(JwtUtil.JwtSubject::getSub).orElse(null);
        String baseAccountId = JwtUtil.dangerousStopgapExtractSubject(baseAccountLinkToken).map(JwtUtil.JwtSubject::getSub).orElse(null);

        return accountClient.linkAccounts(realm, baseAccountId, baseAccountLinkToken, newAccountId, newAccountLinkToken, refreshToken);
    }

}
