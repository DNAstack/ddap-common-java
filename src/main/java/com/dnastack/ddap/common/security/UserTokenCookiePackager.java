package com.dnastack.ddap.common.security;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class UserTokenCookiePackager {

    /**
     * To allow local development without HTTPS, marking cookies as secure is a configurable option.
     */
    private boolean generateSecureCookies;
    private final TextEncryptor encryptor;

    public UserTokenCookiePackager(@Value("${ddap.cookies.secure}") boolean generateSecureCookies,
                                   @Value("${ddap.cookies.encryptor.password}") String encryptorPassword,
                                   @Value("${ddap.cookies.encryptor.salt}") String encryptorSalt) {
        this.generateSecureCookies = generateSecureCookies;
        this.encryptor = Encryptors.text(encryptorPassword, encryptorSalt);
    }

    /**
     * Extracts a security token from the given request, which carries it in an encrypted cookie.
     *
     * @param request the request that originated from the user and probably contains the encrypted DAM token.
     * @param audience A cookie name that describes the collaborating service that honours the token and any service specific usage information
     * @return A string that can be used as a bearer token in a request to DAM, or {@code Optional.empty}
     * if the given request doesn't contain a usable token.
     */
    public Optional<CookieValue> extractToken(ServerHttpRequest request, CookieName audience) {
        Optional<String> token = Optional.ofNullable(request.getCookies().getFirst(audience.cookieName()))
            .map(HttpCookie::getValue);
        return token.map(CookieValue::new);
    }

    public CookieValue extractRequiredToken(ServerHttpRequest request, CookieName audience) {
        return extractToken(request, audience)
                .orElseThrow(() -> new AuthCookieNotPresentInRequestException(audience.cookieName()));
    }

    public <N extends CookieName> Map<N, CookieValue> extractRequiredTokens(ServerHttpRequest request, Set<N> audiences) {
        return audiences.stream()
                .map(audience -> Map.entry(audience, extractRequiredToken(request, audience)))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    /**
     * Encrypts the given security token, and returns the result as a cookie to be set for the given hostname.
     *
     * @param token The token as usable for calling the IC account info endpoints.
     * @param cookieHost The host the returned cookie should target. Should usually point to this DDAP server, since we
     *                  are the only ones who can decrypt the cookie's contents.
     * @param audience A cookie name that describes the collaborating service that honours the token and any service specific usage information
     * @return a cookie that should be sent to the user's browser.
     */
    public ResponseCookie packageToken(String token, String cookieHost, CookieName audience) {
        boolean isStateKind = audience instanceof CookieKind && audience.equals(CookieKind.OAUTH_STATE);
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie
            .from(audience.cookieName(), isStateKind ? token : encryptor.encrypt(token))
            .path("/")
            .secure(generateSecureCookies)
            .httpOnly(true);
        if (cookieHost != null && !cookieHost.isEmpty()) {
            builder.domain(cookieHost);
        }
        return builder.build();
    }

    public ResponseCookie packageToken(String token, CookieName audience) {
        return packageToken(token, null, audience);
    }

    /**
     * Produces a cookie that, when set for the given hostname, clears the corresponding security authorization.
     *
     * @param cookieHost The host the returned cookie should target. Should usually point to this DDAP server, and
     *                   should match the cookieHost passed to {@link #packageToken} on a previous request.
     * @param audience A cookie name that describes the collaborating service that honours the token and any service specific usage information
     * @return a cookie that should be sent to the user's browser to clear their DAM token.
     */
    public ResponseCookie clearToken(String cookieHost, CookieName audience) {
        return ResponseCookie.from(audience.cookieName(), "expired")
                .domain(cookieHost)
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
    }

    public interface CookieName {
        String cookieName();
    }

    public enum CookieKind implements CookieName {
        IC("ic_token"),
        DAM("dam_token"),
        REFRESH("refresh_token"),
        OAUTH_STATE("oauth_state");

        private String cookieName;

        CookieKind(String cookieName) {
            this.cookieName = cookieName;
        }

        public String cookieName() {
            return cookieName;
        }
    }

    @lombok.Value
    public static class CartTokenCookieName implements CookieName {
        private Set<URI> resources;

        @Override
        public String cookieName() {
            return "cart_" + resources.hashCode();
        }
    }

    @RequiredArgsConstructor
    @Getter
    @ToString(exclude = "clearText")
    @EqualsAndHashCode(exclude = "clearText")
    public class CookieValue {
        private final String cipherText;
        private String clearText;

        public String getClearText() {
            if (clearText == null) {
                try {
                    clearText = encryptor.decrypt(cipherText);
                } catch (IllegalArgumentException iae) {
                    throw new PlainTextNotDecryptableException("Unable to decrypt text", iae);
                }
            }

            return clearText;
        }
    }

}
