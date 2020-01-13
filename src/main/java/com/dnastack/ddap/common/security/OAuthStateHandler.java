package com.dnastack.ddap.common.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Duration;
import java.util.*;

import static java.util.Collections.singletonMap;

/**
 * Generates unguessable state values for the beginning of an OAuth 2 authorization code flow
 * and verifies those values when it is time to exchange the auth code for a token.
 */
@Component
public class OAuthStateHandler {

    private static final String DESTINATION_AFTER_LOGIN = "destinationAfterLogin";
    private static final String CLI_SESSION_ID_KEY = "cliSessionId";
    public static final String AUTH_RESOURCE_LIST = "resource";
    private final com.dnastack.ddap.common.security.JwtHandler jwtHandler;

    @Autowired
    public OAuthStateHandler(@Value("${ddap.state-handler.aud}") String tokenAudience,
                             @Value("${ddap.state-handler.ttl}") Duration tokenTtl,
                             @Value("${ddap.state-handler.signingKey}") String tokenSigningKeyBase64) {
        this.jwtHandler = new com.dnastack.ddap.common.security.JwtHandler(tokenAudience,
                                         tokenTtl,
                                         Keys.hmacShaKeyFor(Base64.getMimeDecoder().decode(tokenSigningKeyBase64)));
    }

    public String generateAccountLinkingState(String targetAccountId, String realm) {
        return generateState(TokenExchangePurpose.LINK,
                             realm,
                             singletonMap("targetAccount", targetAccountId));
    }

    public String generateLoginState(URI destinationAfterLogin, String realm) {
        return generateState(TokenExchangePurpose.LOGIN,
                             realm,
                             singletonMap(DESTINATION_AFTER_LOGIN, destinationAfterLogin));
    }

    public String generateResourceState(URI destinationAfterLogin, String realm, List<URI> resources) {
        return generateState(TokenExchangePurpose.RESOURCE_AUTH, realm, Map.of(DESTINATION_AFTER_LOGIN, destinationAfterLogin,
                                                                               AUTH_RESOURCE_LIST, resources));
    }

    public String generateCommandLineLoginState(String cliSessionId, String realm) {
        return generateState(TokenExchangePurpose.CLI_LOGIN,
                             realm,
                             singletonMap(CLI_SESSION_ID_KEY, cliSessionId));
    }


    private String generateState(TokenExchangePurpose purpose, String realm, Map<String, Object> additionalClaims) {
        return jwtHandler.createBuilder(com.dnastack.ddap.common.security.JwtHandler.TokenKind.STATE)
                         .claim("purpose", purpose.toString())
                         .claim("realm", realm)
                         .addClaims(additionalClaims)
                         .compact();
    }

    public ValidatedState parseAndVerify(String stateStringParam, String stateStringCookie) {
        if (!Objects.equals(stateStringParam, stateStringCookie)) {
            throw new InvalidOAuthStateException("CSRF state cookie mismatch", stateStringCookie);
        }
        try {
            Jws<Claims> state = parseStateToken(stateStringParam);
            return new ValidatedState(state.getBody());
        } catch (Exception e) {
            throw new InvalidOAuthStateException("Invalid state token", e, stateStringParam);
        }
    }

    private Jws<Claims> parseStateToken(String jwt) {
        return jwtHandler.createParser(JwtHandler.TokenKind.STATE)
                         .parseClaimsJws(jwt);
    }

    @ToString
    @EqualsAndHashCode
    public static class ValidatedState {
        private final Claims state;

        public ValidatedState(Claims state) {
            this.state = state;
            getTokenExchangePurpose();
            if (getRealm() == null) {
                throw new IllegalStateException("Cannot have null realm in state");
            }
        }

        public TokenExchangePurpose getTokenExchangePurpose() {
            return TokenExchangePurpose.valueOf(state.get("purpose", String.class));
        }

        public String getRealm() {
            return state.get("realm", String.class);
        }

        @SuppressWarnings("unchecked")
        public Optional<List<String>> getResourceList() {
            return Optional.ofNullable(state.get(AUTH_RESOURCE_LIST, List.class));
        }

        public Optional<String> getCliSession() {
            return Optional.ofNullable(state.get(CLI_SESSION_ID_KEY, String.class));
        }

        public Optional<URI> getDestinationAfterLogin() {
            return Optional.ofNullable(state.get(DESTINATION_AFTER_LOGIN, String.class))
                           .map(URI::create);
        }
    }

}
