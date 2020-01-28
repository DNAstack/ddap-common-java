package com.dnastack.ddap.ic.common.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;

@Data
@ConfigurationProperties(prefix = "idp")
public class IdpProperties {

    /**
     * This will be removed once hydra migration is complete.
     *
     * @deprecated Define specific oauth endpoints instead.
     */
    private URI baseUrl;

    /**
     * Authorize url. May contain {@code {realm}} placeholder.
     */
    private String authorizeUrl;

    /**
     * Token url. May contain {@code {realm}} placeholder.
     */
    private String tokenUrl;

    /**
     * Revoke url. May contain {@code {realm}} placeholder.
     */
    private String revokeUrl;

    /**
     * User info url. May be null. May contain {@code {realm}} placeholder.
     */
    private String userInfoUrl;

    private String clientId;
    private String clientSecret;

}
