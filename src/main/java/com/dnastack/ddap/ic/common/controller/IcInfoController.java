package com.dnastack.ddap.ic.common.controller;

import com.dnastack.ddap.ic.common.config.IcProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/v1alpha/icInfo")
@ConditionalOnExpression("${ic.enabled:false}")
public class IcInfoController {
    private IcProperties icProperties;

    @Autowired
    public IcInfoController(IcProperties icProperties) {
        this.icProperties = icProperties;
    }

    @GetMapping
    public Mono<IcInfo> getIcInfo() {
        String icUiUrl = icProperties.getUiUrl().toString();
        return Mono.just(new IcInfo(icUiUrl));
    }
}
