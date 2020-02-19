package com.dnastack.ddap.ic.service;

import com.dnastack.ddap.ic.account.client.ReactiveIcAccountClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@ConditionalOnExpression("${ic.enabled:false}")
public class AccountLinkingService {

    private ReactiveIcAccountClient accountClient;

    @Autowired
    public AccountLinkingService(ReactiveIcAccountClient accountClient) {
        this.accountClient = accountClient;
    }

    public Mono<String> finishAccountLinking(String newAccountLinkToken,
                                             String baseAccountLinkToken,
                                             String realm) {
        return accountClient.linkAccounts(realm, baseAccountLinkToken, newAccountLinkToken);
    }

}
