package com.dnastack.ddap.ic.common.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;

@Data
@ConfigurationProperties(prefix = "ic")
public class IcProperties {

    private URI baseUrl;
    private String clientId;
    private String clientSecret;
    private URI uiUrl;

}
