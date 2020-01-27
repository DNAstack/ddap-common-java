package com.dnastack.ddap.common.security;

public class InapplicableAuthorizationFlowException extends RuntimeException {
    public InapplicableAuthorizationFlowException(String reason) {
        super(reason);
    }
}
