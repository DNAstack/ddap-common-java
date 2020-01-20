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
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieValue;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.OAuthTokenCookie;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.ServiceName;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
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
        return List.of("service", "tokenKind");
    }

    @Override
    public GatewayFilter apply(Config config) {
        requireNonNull(config.getService(), "Must specify service in filter config.");
        requireNonNull(config.getTokenKind(), "Must specify token kind in filter config.");
        final UserTokenCookiePackager.CookieName cookieName = new OAuthTokenCookie(config.getService(), config.getTokenKind());
        return (exchange, chain) -> {
            final ServerHttpRequest request = exchange.getRequest();

            Optional<String> extractedToken = extractCookieValue(cookieName, request);

            if (extractedToken.isPresent()) {
                log.debug("Including {} token in this request", cookieName);
                final String tokenValue = extractedToken.get();

                final ServerHttpRequest requestWithToken = request.mutate()
                    .header("Authorization", format("Bearer %s", tokenValue))
                    .build();
                return chain.filter(exchange.mutate()
                    .request(requestWithToken)
                    .build());
            } else {
                log.debug("No {} token available for this request", cookieName);
                return chain.filter(exchange);
            }
        };
    }

    public Optional<String> extractCookieValue(UserTokenCookiePackager.CookieName cookieName, ServerHttpRequest request) {
        try {
            return cookiePackager.extractToken(request, cookieName)
                                 .map(CookieValue::getClearText);
        } catch (PlainTextNotDecryptableException e) {
            log.debug("Unable to decrypt cookie. Passing through unaltered.");
            return Optional.ofNullable(request.getCookies().getFirst(cookieName.cookieName()))
                           .map(HttpCookie::getValue);
        }
    }

    @Data
    public static class Config {
        private Service service;
        private TokenKind tokenKind;
    }

    public enum Service implements ServiceName {
        IC, DAM;

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }

}
