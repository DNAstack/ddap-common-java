package com.dnastack.ddap.ic.account.client;

import reactor.core.publisher.Mono;

public interface ReactiveLinkingClient {
    Mono<String> linkAccounts(String realm,
                              String baseAccountAccessToken,
                              String newAccountLinkToken);
}
