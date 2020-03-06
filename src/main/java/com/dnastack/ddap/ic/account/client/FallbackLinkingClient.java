package com.dnastack.ddap.ic.account.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/*
 * TODO this shouldn't need to exist. We should refactor linking out of ddap-common
 */
@Slf4j
@Component
@ConditionalOnExpression("not ${ic.enabled:false}")
public class FallbackLinkingClient implements ReactiveLinkingClient {

    @Override
    public Mono<String> linkAccounts(String realm,
                                     String baseAccountAccessToken,
                                     String newAccountLinkToken) {
        return Mono.error(new AssertionError("Linking was attempted, but this deployment does not use an identity concentrator!"));
    }

}
