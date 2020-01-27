package com.dnastack.ddap.common.controller;

import com.dnastack.ddap.common.client.CartCheckoutException;
import com.dnastack.ddap.common.security.*;
import com.dnastack.ddap.common.util.http.XForwardUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import static org.springframework.http.HttpHeaders.SET_COOKIE;

@Slf4j
@ControllerAdvice
public class GlobalExceptionHandler {

    private UserTokenCookiePackager cookiePackager;

    @Autowired
    public GlobalExceptionHandler(UserTokenCookiePackager cookiePackager) {
        this.cookiePackager = cookiePackager;
    }

    @ExceptionHandler(InvalidOAuthStateException.class)
    public ResponseEntity<DdapErrorResponse> handle(ServerHttpRequest request, InvalidOAuthStateException ex) {
        log.info("Failing token exchange due to bad state value " + ex.getStateToken(), ex);
        return ResponseEntity
            .status(400)
            .header(SET_COOKIE, cookiePackager.clearToken(XForwardUtil.getExternalHost(request), ex.getCookieName()).toString())
            .body(new DdapErrorResponse(ex.getMessage(), 400));
    }

    @ExceptionHandler({IllegalArgumentException.class})
    public ResponseEntity<DdapErrorResponse> handle(RuntimeException ex) {
        return ResponseEntity.status(400).body(new DdapErrorResponse(ex.getMessage(), 400));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<DdapErrorResponse> handle(BadCredentialsException ex) {
        return ResponseEntity.status(403).body(new DdapErrorResponse(ex.getMessage(), 403));
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<DdapErrorResponse> handle(InvalidTokenException ex) {
        return ResponseEntity.status(401).body(new DdapErrorResponse(ex.getMessage(), 401));
    }

    @ExceptionHandler(AuthCookieNotPresentInRequestException.class)
    public ResponseEntity<DdapErrorResponse> handle(AuthCookieNotPresentInRequestException ex) {
        return ResponseEntity.status(401).body(new DdapErrorResponse(ex.getMessage(), 401));
    }

    @ExceptionHandler(CartCheckoutException.class)
    public ResponseEntity<DdapErrorResponse> handle(CartCheckoutException ex) {
        return ResponseEntity.status(401).body(new DdapErrorResponse(ex.getMessage(), ex.getStatus()));
    }

    @ExceptionHandler(InapplicableAuthorizationFlowException.class)
    public ResponseEntity<DdapErrorResponse> handle(InapplicableAuthorizationFlowException ex) {
        return ResponseEntity.status(403).body(new DdapErrorResponse(ex.getMessage(), 403));
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    public ResponseEntity<DdapErrorResponse> handle(UnsupportedOperationException ex) {
        return ResponseEntity.status(501).body(new DdapErrorResponse(ex.getMessage(), 501));
    }
}
