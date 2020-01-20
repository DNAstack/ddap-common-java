package com.dnastack.ddap.common.security;

import com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieName;
import lombok.Getter;

/**
 * Thrown when verification of the OAuth state fails. Likely causes: the state has expired or has been tampered with.
 */
public class InvalidOAuthStateException extends RuntimeException {

    @Getter
    private final String stateToken;
    @Getter
    private final CookieName cookieName;

    public InvalidOAuthStateException(String message, String stateToken, CookieName cookieName) {
        super(message);
        this.stateToken = stateToken;
        this.cookieName = cookieName;
    }

    public InvalidOAuthStateException(String message, String stateToken, CookieName cookieName, Exception cause) {
        super(message, cause);
        this.stateToken = stateToken;
        this.cookieName = cookieName;
    }
}
