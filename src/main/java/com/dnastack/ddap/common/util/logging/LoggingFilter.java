package com.dnastack.ddap.common.util.logging;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Set;

@Slf4j
public class LoggingFilter {

    public static void logRoutedRequest(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        log.info(">>> {} {}", request.getMethodValue(), calculateRequestRoute(exchange));
        Set.copyOf(exchange.getRequest()
            .getHeaders()
            .entrySet())
            .stream()
            .map(LogHeaderMessageProcessor::stripSecrets)
            .forEach((headerEntry) -> log.info("  {}: {}", headerEntry.getKey(), headerEntry.getValue()));
    }

    private static URI calculateRequestRoute(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        URI requestUri = request.getURI();

        Route gatewayRoute = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        URI routeUri = gatewayRoute == null ? requestUri : gatewayRoute.getUri();

        return UriComponentsBuilder.fromUri(routeUri)
            .replacePath(requestUri.getPath())
            .replaceQuery(requestUri.getQuery())
            .build()
            .toUri();
    }

    public static ExchangeFilterFunction logRequest() {
        return ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
            log.info(">>> {} {}", clientRequest.method(), clientRequest.url());
            Set.copyOf(clientRequest.headers()
                .entrySet())
                .stream()
                .map(LogHeaderMessageProcessor::stripSecrets)
                .forEach((headerEntry) -> log.info("  {}: {}", headerEntry.getKey(), headerEntry.getValue()));
            return Mono.just(clientRequest);
        });
    }

    public static ExchangeFilterFunction logResponse() {
        return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
            log.info("<<< HTTP {}", clientResponse.rawStatusCode());
            Set.copyOf(clientResponse.headers()
                .asHttpHeaders()
                .entrySet())
                .stream()
                .map(LogHeaderMessageProcessor::stripSecrets)
                .forEach((headerEntry) -> log.info("  {}: {}", headerEntry.getKey(), headerEntry.getValue()));
            return Mono.just(clientResponse);
        });
    }

}
