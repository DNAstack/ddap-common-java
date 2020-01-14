package com.dnastack.ddap.common.client;

import com.dnastack.ddap.common.config.DamProperties;
import dam.v1.DamService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.util.UriTemplate;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
public class ReactiveDamClient {

    private URI damBaseUrl;
    private String damClientId;
    private String damClientSecret;
    public URI damUiUrl;
    private AuthAwareWebClientFactory webClientFactory;

    public ReactiveDamClient(DamProperties properties, AuthAwareWebClientFactory webClientFactory) {
        this(
                properties.getBaseUrl(),
                properties.getClientId(),
                properties.getClientSecret(),
                URI.create(properties.getUiUrl()),
                webClientFactory
        );
    }

    public ReactiveDamClient(URI damBaseUrl,
                             String damClientId,
                             String damClientSecret,
                             URI damUiUrl,
                             AuthAwareWebClientFactory webClientFactory) {
        this.damBaseUrl = damBaseUrl;
        this.damClientId = damClientId;
        this.damClientSecret = damClientSecret;
        this.damUiUrl = damUiUrl;
        this.webClientFactory = webClientFactory;
    }

    public Mono<DamService.GetInfoResponse> getDamInfo() {
        return WebClientFactory.getWebClient()
            .get()
            .uri(damBaseUrl.resolve("/dam"))
            .retrieve()
            .bodyToMono(String.class)
            .flatMap(json -> ProtobufDeserializer.fromJson(json, DamService.GetInfoResponse.getDefaultInstance()));
    }

    public Mono<Map<String, DamService.Resource>> getResources(String realm) {
        final UriTemplate template = new UriTemplate("/dam/v1alpha/{realm}/resources" +
            "?client_id={clientId}" +
            "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("clientId", damClientId);
        variables.put("clientSecret", damClientSecret);

        return WebClientFactory.getWebClient()
            .get()
            .uri(damBaseUrl.resolve(template.expand(variables)))
            .retrieve()
            .bodyToMono(String.class)
            .flatMap(json -> ProtobufDeserializer.fromJson(json, DamService.GetResourcesResponse.getDefaultInstance()))
            .map(DamService.GetResourcesResponse::getResourcesMap);
    }

    public Mono<DamService.Resource> getResource(String realm, String resourceId) {
        final UriTemplate template = new UriTemplate("/dam/v1alpha/{realm}/resources/{resourceId}" +
            "?client_id={clientId}" +
            "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("resourceId", resourceId);
        variables.put("clientId", damClientId);
        variables.put("clientSecret", damClientSecret);

        return WebClientFactory.getWebClient()
            .get()
            .uri(damBaseUrl.resolve(template.expand(variables)))
            .retrieve()
            .bodyToMono(String.class)
            .flatMap(json -> ProtobufDeserializer.fromJson(json, DamService.GetResourceResponse.getDefaultInstance()))
            .map(DamService.GetResourceResponse::getResource);
    }

    public Mono<Map<String, DamService.View>> getResourceViews(String realm,
                                                               String resourceId,
                                                               String damToken,
                                                               String refreshToken) {
        final UriTemplate template = new UriTemplate("/dam/v1alpha/{realm}/resources/{resourceId}/views" +
            "?client_id={clientId}" +
            "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("resourceId", resourceId);
        variables.put("clientId", damClientId);
        variables.put("clientSecret", damClientSecret);

        return webClientFactory.getWebClient(realm, refreshToken, OAuthFilter.Audience.IC)
            .get()
            .uri(damBaseUrl.resolve(template.expand(variables)))
            .header(AUTHORIZATION, "Bearer " + damToken)
            .retrieve()
            .bodyToMono(String.class)
            .flatMap(json -> ProtobufDeserializer.fromJson(json, DamService.GetViewsResponse.getDefaultInstance()))
            .map(DamService.GetViewsResponse::getViewsMap);
    }

    @Deprecated(forRemoval = true)
    public Mono<DamService.ResourceTokens.ResourceToken> getAccessTokenForView(String realm,
                                                                               String resourceId,
                                                                               String viewId,
                                                                               String damToken,
                                                                               String refreshToken) {
        final UriTemplate template = new UriTemplate(
            "/dam/v1alpha/{realm}/resources/{resourceId}/views/{viewId}/token" +
                "?client_id={clientId}" +
                "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("resourceId", resourceId);
        variables.put("viewId", viewId);
        variables.put("clientId", damClientId);
        variables.put("clientSecret", damClientSecret);

        return webClientFactory.getWebClient(realm, refreshToken, OAuthFilter.Audience.IC)
            .get()
            .uri(damBaseUrl.resolve(template.expand(variables)))
            .header(AUTHORIZATION, "Bearer " + damToken)
            .retrieve()
            .bodyToMono(String.class)
            .flatMap(json -> ProtobufDeserializer.fromJson(json, DamService.ResourceTokens.ResourceToken.getDefaultInstance()));
    }

    public Mono<Map<String, DamService.GetFlatViewsResponse.FlatView>> getFlattenedViews(String realm) {
        final UriTemplate template = new UriTemplate("/dam/v1alpha/{realm}/flatViews" +
            "?client_id={clientId}" +
            "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("realm", realm);
        variables.put("clientId", damClientId);
        variables.put("clientSecret", damClientSecret);

        return WebClientFactory.getWebClient()
            .get()
            .uri(damBaseUrl.resolve(template.expand(variables)))
            .retrieve()
            .bodyToMono(String.class)
            .flatMap(json -> ProtobufDeserializer.fromJson(json, DamService.GetFlatViewsResponse.getDefaultInstance()))
            .map(DamService.GetFlatViewsResponse::getViewsMap);
    }

    // FIXME update proto and return checkout object
    public Mono<Object> checkoutCart(String cartToken) {
        final UriTemplate template = new UriTemplate("/dam/checkout" +
            "?client_id={clientId}" +
            "&client_secret={clientSecret}");
        final Map<String, Object> variables = new HashMap<>();
        variables.put("clientId", damClientId);
        variables.put("clientSecret", damClientSecret);

        return WebClientFactory.getWebClient()
            .post()
            .uri(damBaseUrl.resolve(template.expand(variables)))
            .header(AUTHORIZATION, "Bearer " + cartToken)
            .retrieve()
            .bodyToMono(Object.class);
    }

}
