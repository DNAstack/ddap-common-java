package com.dnastack.ddap.common.config;

import com.dnastack.ddap.common.proxy.LoggingGatewayFilterFactory;
import com.dnastack.ddap.common.proxy.SetBearerTokenFromCookieGatewayFilterFactory;
import com.dnastack.ddap.common.proxy.TimeoutAndRetryGatewayFilterFactory;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

import static com.dnastack.ddap.common.proxy.SetBearerTokenFromCookieGatewayFilterFactory.Service.IC;
import static java.lang.String.format;

@Configuration
public class DamRouter {

    @Autowired
    @Qualifier("dams")
    private Map<String, DamProperties> dams;

    @Autowired
    private TimeoutAndRetryGatewayFilterFactory timeoutAndRetryFilterFactory;

    @Autowired
    private LoggingGatewayFilterFactory loggingFilterFactory;

    @Autowired
    private SetBearerTokenFromCookieGatewayFilterFactory bearerTokenFilterFactory;

    @Bean
    public RouteLocator damRoutes(RouteLocatorBuilder builder) {
        // TODO: DISCO-2347 read from config
        final TimeoutAndRetryGatewayFilterFactory.RetryConfig timeoutAndRetryConfig = new TimeoutAndRetryGatewayFilterFactory.RetryConfig();
        timeoutAndRetryConfig.setRetries(2);
        timeoutAndRetryConfig.setMinimumTimeout(1000);
        timeoutAndRetryConfig.setMaximumTimeout(20000);
        timeoutAndRetryConfig.setTimeoutExponentialScalingBase(10);

        final GatewayFilter timeoutAndRetryFilter = timeoutAndRetryFilterFactory.apply(timeoutAndRetryConfig);

        final GatewayFilter loggingFilter = loggingFilterFactory.apply(new Object());

        final SetBearerTokenFromCookieGatewayFilterFactory.Config bearerTokenConfig = new SetBearerTokenFromCookieGatewayFilterFactory.Config();
        bearerTokenConfig.setService(IC);
        bearerTokenConfig.setTokenKind(TokenKind.IDENTITY);
        final GatewayFilter bearerTokenFilter = bearerTokenFilterFactory.apply(bearerTokenConfig);

        RouteLocatorBuilder.Builder routesBuilder = builder.routes();
        for (Map.Entry<String, DamProperties> entry : dams.entrySet()) {
            final String id = entry.getKey();
            final DamProperties dam = entry.getValue();
            routesBuilder =
                    routesBuilder
                            .route(id,
                                   r -> r.path(format("/dam/%s/**", id))
                                         .filters(f -> f.filter(timeoutAndRetryFilter)
                                                        .filter(loggingFilter)
                                                        .rewritePath("^/dam/[^/]+/", "/dam/")
                                                        .addRequestParameter("clientId",
                                                                             dam.getClientId())
                                                        .addRequestParameter("clientSecret",
                                                                             dam.getClientSecret())
                                                        .removeRequestHeader("Authorization")
                                                        .filter(bearerTokenFilter)
                                         )
                                         .uri(dam.getBaseUrl()));
        }
        return routesBuilder.build();
    }

}
