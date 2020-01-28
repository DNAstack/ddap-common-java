package com.dnastack.ddap.ic.account.client;

import com.dnastack.ddap.common.client.AuthAwareWebClientFactory;
import com.dnastack.ddap.common.client.OAuthFilter;
import com.dnastack.ddap.common.client.ProtobufDeserializer;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieValue;
import com.dnastack.ddap.ic.common.config.IcProperties;
import ic.v1.IcService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriTemplate;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

/*
 * TODO move this to ddap-ic-admin. Not needed by other deployments anymore.
 */
@Slf4j
@Component
@ConditionalOnExpression("${ic.enabled:false}")
public class ReactiveIcAccountClient {

    private IcProperties icProperties;
    private AuthAwareWebClientFactory webClientFactory;

    public ReactiveIcAccountClient(IcProperties icProperties, AuthAwareWebClientFactory webClientFactory) {
        this.icProperties = icProperties;
        this.webClientFactory = webClientFactory;
    }

    public Mono<IcService.AccountResponse> getAccounts(String realm, CookieValue icToken, CookieValue refreshToken) {
        final UriTemplate template = new UriTemplate("/identity/v1alpha/{realm}/accounts/-" +
                "?client_id={clientId}" +
                "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("clientId", icProperties.getClientId());
        variables.put("clientSecret", icProperties.getClientSecret());

        final String refreshTokenClearText = Optional.ofNullable(refreshToken)
                                                     .map(CookieValue::getClearText)
                                                     .orElse(null);
        return webClientFactory.getWebClient(realm, null, OAuthFilter.Audience.IC)
                               .get()
                               .uri(icProperties.getBaseUrl().resolve(template.expand(variables)))
                               .header(AUTHORIZATION, "Bearer " + icToken.getClearText())
                               .retrieve()
                               .bodyToMono(String.class)
                               .flatMap(json -> ProtobufDeserializer.fromJsonToMono(json, IcService.AccountResponse.getDefaultInstance()));
    }

    public Mono<String> linkAccounts(String realm,
                                     String baseAccountId,
                                     String baseAccountAccessToken,
                                     String newAccountId,
                                     String newAccountLinkToken,
                                     String refreshToken) {
        final UriTemplate template = new UriTemplate("/identity/v1alpha/{realm}/accounts/{accountId}" +
                "?client_id={clientId}" +
                "&client_secret={clientSecret}" +
                "&link_token={linkToken}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("accountId", baseAccountId);
        variables.put("linkToken", newAccountLinkToken);
        variables.put("clientId", icProperties.getClientId());
        variables.put("clientSecret", icProperties.getClientSecret());

        return webClientFactory.getWebClient(realm, refreshToken, OAuthFilter.Audience.IC)
                .patch()
                .uri(icProperties.getBaseUrl().resolve(template.expand(variables)))
                .header(AUTHORIZATION, "Bearer " + baseAccountAccessToken)
                .exchange()
                .flatMap(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return Mono.just(format("Successfully linked [%s] into base account [%s]", newAccountId, baseAccountId));
                    } else {
                        return response.bodyToMono(String.class)
                                .flatMap(errorMessage -> Mono.error(new AccountLinkingFailedException("Link failed: " + errorMessage)));
                    }
                });
    }

    public Mono<String> unlinkAccount(String realm,
                                      String accountId,
                                      String accountAccessToken,
                                      String refreshToken,
                                      String subjectName) {
        final UriTemplate template = new UriTemplate("/identity/v1alpha/{realm}/accounts/{accountId}/subjects/{subjectName}" +
                "?client_id={clientId}" +
                "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("accountId", accountId);
        variables.put("subjectName", subjectName);
        variables.put("clientId", icProperties.getClientId());
        variables.put("clientSecret", icProperties.getClientSecret());

        return webClientFactory.getWebClient(realm, refreshToken, OAuthFilter.Audience.IC)
                .delete()
                .uri(icProperties.getBaseUrl().resolve(template.expand(variables)))
                .header(AUTHORIZATION, "Bearer " + accountAccessToken)
                .exchange()
                .flatMap(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return Mono.just(format("Successfully unlinked [%s] from account [%s]", subjectName, accountId));
                    } else {
                        return response.bodyToMono(String.class)
                                .flatMap(errorMessage -> Mono.error(new AccountLinkingFailedException("Unlink failed: " + errorMessage)));
                    }
                });
    }

}
