package com.dnastack.ddap.common.client;

import com.dnastack.ddap.common.util.logging.LoggingFilter;
import org.springframework.cloud.gateway.support.TimeoutException;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

import static com.dnastack.ddap.common.util.TimeoutUtil.timeout;

public class WebClientFactory {

    private static final int MAX_IN_MEMORY_SIZE = 10 * 1024 * 1024; // 10MB

    public static WebClient.Builder getWebClientBuilder() {
        return WebClient.builder()
            .exchangeStrategies(ExchangeStrategies.builder()
                .codecs(configurer -> configurer
                    .defaultCodecs()
                    .maxInMemorySize(MAX_IN_MEMORY_SIZE))
                .build())
            .filter((request, next) -> {
                switch (request.method()) {
                    case GET:
                    case HEAD:
                    case OPTIONS:
                        return timeout(next.exchange(request), Duration.ofSeconds(1))
                            .onErrorResume(TimeoutException.class, ex -> timeout(next.exchange(request), Duration.ofSeconds(10)))
                            .onErrorResume(TimeoutException.class, ex -> timeout(next.exchange(request), Duration.ofSeconds(30)))
                            .onErrorResume(TimeoutException.class, ex -> timeout(next.exchange(request), Duration.ofSeconds(80)));
                    default:
                        return next.exchange(request);
                }
            })
            .filter(LoggingFilter.logRequest())
            .filter(LoggingFilter.logResponse());
    }

    public static WebClient getWebClient() {
        return WebClientFactory.getWebClientBuilder()
            .exchangeStrategies(ExchangeStrategies.builder()
                .codecs(configurer -> configurer
                    .defaultCodecs()
                    .maxInMemorySize(MAX_IN_MEMORY_SIZE))
                .build())
            .build();
    }

}
