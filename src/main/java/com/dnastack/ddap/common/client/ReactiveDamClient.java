package com.dnastack.ddap.common.client;

import dam.v1.DamService;
import reactor.core.publisher.Mono;

import java.util.Map;

public interface ReactiveDamClient {
    Mono<DamService.GetInfoResponse> getDamInfo();

    Mono<Map<String, DamService.Resource>> getResources(String realm);

    Mono<DamService.Resource> getResource(String realm, String resourceId);

    Mono<Map<String, DamService.View>> getResourceViews(String realm,
                                                        String resourceId,
                                                        String damToken,
                                                        String refreshToken);

    @Deprecated(forRemoval = true)
    Mono<DamService.ResourceTokens.ResourceToken> getAccessTokenForView(String realm,
                                                                        String resourceId,
                                                                        String viewId,
                                                                        String damToken,
                                                                        String refreshToken);

    Mono<Map<String, DamService.GetFlatViewsResponse.FlatView>> getFlattenedViews(String realm);

    // FIXME update proto and return checkout object
    Mono<DamService.ResourceTokens> checkoutCart(String cartToken);
}
