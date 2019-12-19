/*
 * Copyright 2013-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.dnastack.ddap.common.proxy;

import com.dnastack.ddap.common.security.PlainTextNotDecryptableException;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieKind;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieValue;
import com.dnastack.ddap.common.util.http.XForwardUtil;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

@Slf4j
@Component
public class SetBearerTokenFromCookieGatewayFilterFactory extends AbstractGatewayFilterFactory<SetBearerTokenFromCookieGatewayFilterFactory.Config> {

    private UserTokenCookiePackager cookiePackager;

    @Autowired
    public SetBearerTokenFromCookieGatewayFilterFactory(UserTokenCookiePackager cookiePackager) {
        super(Config.class);
        this.cookiePackager = cookiePackager;
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return singletonList("cookieKind");
    }

    @Override
    public GatewayFilter apply(Config config) {
        requireNonNull(config.getCookieKind(), "Must specify token audience in filter config.");
        return (exchange, chain) -> {
            final ServerHttpRequest request = exchange.getRequest();

            Optional<CookieValue> extractedToken = cookiePackager.extractToken(request, config.getCookieKind());

            if (extractedToken.isPresent()) {
                log.debug("Including {} token in this request", config.getCookieKind());
                final CookieValue token = extractedToken.get();
                String tokenValue;

                try {
                    tokenValue = token.getClearText();
                } catch (PlainTextNotDecryptableException ptnde) {
                    log.info("Request was made with stale {} token. Passing through with original cookie value.", config.getCookieKind());
                    tokenValue = token.getCipherText();
                }

                final ServerHttpRequest requestWithToken = request.mutate()
                    .header("Authorization", format("Bearer %s", tokenValue))
                    .build();
                return chain.filter(exchange.mutate()
                    .request(requestWithToken)
                    .build());
            } else {
                log.debug("No {} token available for this request", config.getCookieKind());
                return chain.filter(exchange);
            }
        };
    }

    @Data
    public static class Config {
        private CookieKind cookieKind;
    }

}
