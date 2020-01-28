package com.dnastack.ddap.ic.account.service;

import com.dnastack.ddap.ic.account.model.IdentityModel;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.PathVariable;
import reactor.core.publisher.Mono;

public interface IdentityService {
    Mono<IdentityModel> getIdentity(ServerHttpRequest request, @PathVariable String realm);
}
