package com.dnastack.ddap.common.util.logging;

import lombok.extern.slf4j.Slf4j;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.DAM;
import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.IC;
import static com.dnastack.ddap.common.security.UserTokenCookiePackager.CookieName;
import static com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;

@Slf4j
public class LogHeaderMessageProcessor {

    private static final String SECRET_STRIPPED_CHAR_SEQUENCE = "***";
    private static final boolean EXCLUDE_SECRETS = Boolean.parseBoolean(
        optionalEnv("DDAP_LOGGING_EXCLUDE_SECRETS", "true")
    );

    private static String optionalEnv(String name, String defaultValue) {
        String val = System.getenv(name);
        if (val == null) {
            return defaultValue;
        }
        return val;
    }

    public static Map.Entry<String, List<String>> stripSecrets(Map.Entry<String, List<String>> headerEntry) {
        if (!EXCLUDE_SECRETS) {
            return headerEntry;
        }

        try {
            if ("Authorization".equalsIgnoreCase(headerEntry.getKey())) {
                return stripSecretsFromAuthorizationHeader(headerEntry);
            }
            if ("Cookie".equalsIgnoreCase(headerEntry.getKey())) {
                return stripSecretsFromCookieHeader(headerEntry);
            }
        } catch (Exception ex) {
            log.error("Failed to strip secrets of '{}' header due to", headerEntry.getKey(), ex);
            return headerEntry;
        }

        return headerEntry;
    }

    private static Map.Entry<String, List<String>> stripSecretsFromAuthorizationHeader(Map.Entry<String, List<String>> headerEntry) {
        String authHeaderValue = headerEntry.getValue().get(0);
        String[] authHeaderValueTokenized = authHeaderValue.split(" ");
        if (authHeaderValueTokenized.length > 1) {
            String authorizationType = authHeaderValueTokenized[0];
            return Map.entry(headerEntry.getKey(), List.of(authorizationType + " " + SECRET_STRIPPED_CHAR_SEQUENCE));
        } else {
            return Map.entry(headerEntry.getKey(), List.of(SECRET_STRIPPED_CHAR_SEQUENCE));
        }
    }

    private static Map.Entry<String, List<String>> stripSecretsFromCookieHeader(Map.Entry<String, List<String>> headerEntry) {
        List<String> modifiedCookieValue = headerEntry.getValue()
            .stream()
            .map((headerValue) -> {
                String[] cookies = headerValue.split(";");
                return Stream.of(cookies)
                    .map((cookie) -> {
                        String cookieName = cookie.split("=")[0].trim();
                        String cookieValue = cookie.split("=")[1].trim();
                        return Map.entry(cookieName, cookieValue);
                    })
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            })
            .map(Map::entrySet)
            .flatMap(Collection::stream)
            .map((cookie) -> {
                boolean containsSecrets = Stream.of(
                    IC.cookieName(TokenKind.ACCESS), IC.cookieName(TokenKind.IDENTITY),
                    IC.cookieName(TokenKind.OAUTH_STATE), IC.cookieName(TokenKind.REFRESH),
                    DAM.cookieName(TokenKind.ACCESS), DAM.cookieName(TokenKind.IDENTITY),
                    DAM.cookieName(TokenKind.OAUTH_STATE), DAM.cookieName(TokenKind.REFRESH)
                )
                    .map(CookieName::cookieName)
                    .anyMatch((sensitiveCookieName) -> sensitiveCookieName.equalsIgnoreCase(cookie.getKey()));
                if (containsSecrets) {
                    return cookie.getKey() + "=" + SECRET_STRIPPED_CHAR_SEQUENCE;
                }
                return cookie.getKey() + "=" + cookie.getValue();
            })
            .collect(Collectors.toUnmodifiableList());
        return Map.entry(headerEntry.getKey(), modifiedCookieValue);
    }

}
