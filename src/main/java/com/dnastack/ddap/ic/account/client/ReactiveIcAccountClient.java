package com.dnastack.ddap.ic.account.client;

import com.dnastack.ddap.common.client.AuthAwareWebClientFactory;
import com.dnastack.ddap.common.client.OAuthFilter;
import com.dnastack.ddap.common.client.ProtobufDeserializer;
import com.dnastack.ddap.common.client.WebClientFactory;
import com.dnastack.ddap.common.exception.ServiceOutage;
import com.dnastack.ddap.common.security.BadCredentialsException;
import com.dnastack.ddap.common.security.InvalidTokenException;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieValue;
import com.dnastack.ddap.ic.common.config.IcProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.UriTemplate;
import reactor.core.publisher.Mono;
import scim.v2.Users;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON;

/*
 * TODO move this to ddap-ic-admin. Not needed by other deployments anymore.
 */
@Slf4j
@Component
@ConditionalOnExpression("${ic.enabled:false}")
public class ReactiveIcAccountClient implements ReactiveLinkingClient {

    private static final UriTemplate SCIM_ME_TEMPLATE = new UriTemplate("/scim/v2/{realm}/Me" +
                                                         "?client_id={clientId}" +
                                                         "&client_secret={clientSecret}");
    private IcProperties icProperties;
    private AuthAwareWebClientFactory webClientFactory;

    public ReactiveIcAccountClient(IcProperties icProperties, AuthAwareWebClientFactory webClientFactory) {
        this.icProperties = icProperties;
        this.webClientFactory = webClientFactory;
    }

    public Mono<Users.User> getAccounts(String realm, CookieValue icToken, CookieValue refreshToken) {
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("clientId", icProperties.getClientId());
        variables.put("clientSecret", icProperties.getClientSecret());

        final String refreshTokenClearText = Optional.ofNullable(refreshToken)
                                                     .map(CookieValue::getClearText)
                                                     .orElse(null);
        return webClientFactory.getWebClient(realm, null, OAuthFilter.Audience.IC)
                               .get()
                               .uri(icProperties.getBaseUrl().resolve(SCIM_ME_TEMPLATE.expand(variables)))
                               .header(AUTHORIZATION, "Bearer " + icToken.getClearText())
                               .retrieve()
                               .bodyToMono(String.class)
                               .flatMap(json -> ProtobufDeserializer.fromJsonToMono(json, Users.User.getDefaultInstance()));
    }

    public Mono<IcUserInfo> getUserInfo(String accessToken) {
        final URI uri = icProperties.getBaseUrl().resolve("/userinfo");
        return WebClientFactory.getWebClient()
                               .get()
                               .uri(uri)
                               .header(AUTHORIZATION, "Bearer " + accessToken)
                               .accept(APPLICATION_JSON)
                               .exchange()
                               .flatMap(response -> {
                                   if (response.statusCode().is2xxSuccessful()) {
                                       return response.bodyToMono(IcUserInfo.class);
                                   } else if (response.statusCode().equals(HttpStatus.UNAUTHORIZED)) {
                                       return response.bodyToMono(String.class)
                                                      .flatMap(body -> Mono.error(new InvalidTokenException(body)));
                                   } else if (response.statusCode().equals(HttpStatus.FORBIDDEN)) {
                                       return response.bodyToMono(String.class)
                                                      .flatMap(body -> Mono.error(new BadCredentialsException(body)));

                                   } else {
                                       return response.bodyToMono(String.class)
                                                      .flatMap(body -> Mono.error(new ServiceOutage(body)));
                                   }
                               });
    }

    @Override
    public Mono<String> linkAccounts(String realm,
                                     String baseAccountAccessToken,
                                     String newAccountLinkToken) {
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("clientId", icProperties.getClientId());
        variables.put("clientSecret", icProperties.getClientSecret());

        final Map<String, Object> body = new HashMap<>();
        body.put("schemas", List.of("urn:ietf:params:scim:api:messages:2.0:PatchOp"));
        body.put("Operations", List.of(Map.of(
            "op", "add",
            "path", "emails",
            "value", "X-Link-Authorization"
        )));

        return WebClientFactory.getWebClient()
            .patch()
            .uri(icProperties.getBaseUrl().resolve(SCIM_ME_TEMPLATE.expand(variables)))
            .header(AUTHORIZATION, "Bearer " + baseAccountAccessToken)
            .header("X-Link-Authorization", "Bearer " + newAccountLinkToken)
            .body(BodyInserters.fromObject(body))
            .exchange()
            .flatMap(response -> {
                if (response.statusCode().is2xxSuccessful()) {
                    return Mono.just("Successfully linked accounts");
                } else {
                    return response.bodyToMono(String.class)
                        .flatMap(errorMessage -> Mono.error(new AccountLinkingFailedException("Link failed: " + errorMessage)));
                }
            });
    }

}
