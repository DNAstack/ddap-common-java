package com.dnastack.ddap.common.client;

import lombok.Getter;

public class CartCheckoutException extends RuntimeException {
    @Getter
    private final int status;

    public CartCheckoutException(String message, int status, Throwable cause) {
        super(message, cause);
        this.status = status;
    }
}
