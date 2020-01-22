package com.dnastack.ddap.common.controller;

import com.dnastack.ddap.common.client.ReactiveDamClient;
import com.dnastack.ddap.common.config.DamProperties;
import com.dnastack.ddap.common.util.http.UriUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1alpha/realm/{realm}/dam")
public class DamInfoController {

    private Map<String, ReactiveDamClient> damClients;
    private final Map<String, DamProperties> damPropertiesMap;

    @Autowired
    public DamInfoController(Map<String, ReactiveDamClient> damClients,
                             @Qualifier("dams") Map<String, DamProperties> damPropertiesMap) {
        this.damClients = damClients;
        this.damPropertiesMap = damPropertiesMap;
    }

    @GetMapping
    public Mono<DamsInfo> getDamInfo(ServerHttpRequest request, @PathVariable String realm) {
        return Flux.fromStream(damClients.entrySet().stream())
                   .flatMap(e -> {
                       final String damId = e.getKey();
                       final ReactiveDamClient damClient = e.getValue();
                       final String damUiUrl = damPropertiesMap.get(damId).getUiUrl();
                       return damClient.getDamInfo()
                                       .map(damInfoResponse -> {

                                           final String url = UriUtil.selfLinkToDam(request, damId)
                                                                     .toString();
                                           final String label = Optional.ofNullable(damInfoResponse.getUiMap())
                                                                        .map(ui -> ui.get("label"))
                                                                        // If you use orElseGet here you will run into a compilation error on Java 11
                                                                        // Issue is not present using Java 12
                                                                        .orElse(damInfoResponse.getName());
                                           return new DamInfo(damId, label, url, damUiUrl);
                                       });
                   })
                   .collect(Collectors.toMap(DamInfo::getId, Function.identity()))
                   .map(DamsInfo::new);
    }
}
