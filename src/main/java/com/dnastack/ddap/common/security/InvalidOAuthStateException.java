package com.dnastack.ddap.common.security;

import lombok.Getter;

/**
 * Thrown when verification of the OAuth state fails. Likely causes: the state has expired or has been tampered with.
 */
public class InvalidOAuthStateException extends RuntimeException {

    @Getter
    private final String stateToken;

    public InvalidOAuthStateException(String message, String stateToken) {
        super(message);
        this.stateToken = stateToken;
    }

    public InvalidOAuthStateException(String message, Exception cause, String stateToken) {
        super(message, cause);
        this.stateToken = stateToken;
    }
}
