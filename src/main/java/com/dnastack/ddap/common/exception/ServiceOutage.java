package com.dnastack.ddap.common.exception;

public class ServiceOutage extends RuntimeException {
    public ServiceOutage() {
    }

    public ServiceOutage(String message) {
        super(message);
    }

    public ServiceOutage(String message, Throwable cause) {
        super(message, cause);
    }

    public ServiceOutage(Throwable cause) {
        super(cause);
    }
}
