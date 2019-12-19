package com.dnastack.ddap.common.security;

public class PlainTextNotDecryptableException extends RuntimeException {

    public PlainTextNotDecryptableException() {
        super();
    }

    public PlainTextNotDecryptableException(String message, Throwable cause) {
        super(message, cause);
    }
}
