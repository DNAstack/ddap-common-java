package com.dnastack.ddap.common.config;

import lombok.Data;

import java.net.URI;

@Data
public class DamProperties {

    private URI baseUrl;
    private String clientId;
    private String clientSecret;
    private String uiUrl;

}
