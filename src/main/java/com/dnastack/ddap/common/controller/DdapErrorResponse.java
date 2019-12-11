package com.dnastack.ddap.common.controller;

import lombok.Value;

@Value
public class DdapErrorResponse {
    String message;
    int statusCode;
}
