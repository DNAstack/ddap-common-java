package com.dnastack.ddap.common.security;

public class PlainTextNotDecryptableException extends Exception {

    public PlainTextNotDecryptableException() {
        super();
    }

    public PlainTextNotDecryptableException(Throwable cause) {
        super(cause);
    }

    public PlainTextNotDecryptableException(String message, Throwable cause) {
        super(message, cause);
    }
}
