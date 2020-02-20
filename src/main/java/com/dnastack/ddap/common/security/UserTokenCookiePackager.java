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
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

@Slf4j
@Component
public class UserTokenCookiePackager {

    public static final String LINK_TOKEN_COOKIE_NAME = "LINK";

    /**
     * To allow local development without HTTPS, marking cookies as secure is a configurable option.
     */
    private boolean generateSecureCookies;
    private final BytesEncryptor encryptor;

    public UserTokenCookiePackager(@Value("${ddap.cookies.secure}") boolean generateSecureCookies,
                                   @Value("${ddap.cookies.encryptor.password}") String encryptorPassword,
                                   @Value("${ddap.cookies.encryptor.salt}") String encryptorSalt) {
        this.generateSecureCookies = generateSecureCookies;
        this.encryptor = Encryptors.standard(encryptorPassword, encryptorSalt);
    }

    /**
     * Extracts a security token from the given request, which carries it in an encrypted cookie.
     *
     * @param request the request that originated from the user and probably contains the encrypted DAM token.
     * @param audience A cookie name that describes the collaborating service that honours the token and any service specific usage information
     * @return A string that can be used as a bearer token in a request to DAM, or {@code Optional.empty}
     * if the given request doesn't contain a usable token.
     * @throws PlainTextNotDecryptableException If the cookie value cannot be properly decoded.
     */
    public Optional<CookieValue> extractToken(ServerHttpRequest request, CookieName audience) throws PlainTextNotDecryptableException {
        // FIXME this API (returning Optional and throwing checked exception) sucks.
        // We should probably move away from Optional to a type that encapsulate all states (not present, present+invalid, present+valid)
        final Optional<String> foundCookieValue = Optional.ofNullable(request.getCookies().getFirst(audience.cookieName()))
                                                          .map(HttpCookie::getValue);
        if (foundCookieValue.isPresent()) {
            final String cookie = foundCookieValue.get();
            final String clearText = decodeToken(cookie);
            return Optional.of(new CookieValue(cookie, clearText));
        } else {
            return Optional.empty();
        }
    }

    /**
     * Extracts a security token from the given request, which carries it in an encrypted cookie.
     *
     * @param request the request that originated from the user and probably contains the encrypted DAM token.
     * @param audience A cookie name that describes the collaborating service that honours the token and any service specific usage information
     * @return A string that can be used as a bearer token in a request to DAM, or {@code Optional.empty}
     * if the given request doesn't contain a usable token.
     */
    public Optional<CookieValue> extractTokenIgnoringInvalid(ServerHttpRequest request, CookieName audience) {
        try {
            return extractToken(request, audience);
        } catch (PlainTextNotDecryptableException e) {
            return Optional.empty();
        }
    }

    /**
     * Encodes token as encrypted/compressed value without packaging it in a cookie.
     * Most users should prefer {@link #packageToken(String, CookieName)}.
     */
    public String encodeToken(String token) {
        return encrypt(compressToken(token));
    }

    /**
     * Decodes token encrypted/compressed value.
     * Most users should prefer {@link #extractToken(ServerHttpRequest, CookieName)}.
     */
    public String decodeToken(String cookie) throws PlainTextNotDecryptableException {
        try {
            return decompressToken(decrypt(cookie));
        } catch (Exception e) {
            throw new PlainTextNotDecryptableException(e);
        }
    }

    public CookieValue extractRequiredToken(ServerHttpRequest request, CookieName audience) {
        try {
            return extractToken(request, audience)
                    .orElseThrow(() -> new AuthCookieNotPresentInRequestException(audience.cookieName()));
        } catch (PlainTextNotDecryptableException e) {
            throw new AuthCookieNotPresentInRequestException(audience.cookieName());
        }
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
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie
            .from(audience.cookieName(), audience.encoded() ? encodeToken(token) : token)
            .path("/")
            .secure(generateSecureCookies)
            .httpOnly(true);
        if (cookieHost != null && !cookieHost.isEmpty()) {
            builder.domain(cookieHost);
        }
        return builder.build();
    }

    private String encrypt(byte[] input) {
        return Base64.getEncoder().withoutPadding().encodeToString(encryptor.encrypt(input));
    }

    byte[] compressToken(String token) {
        final byte[] input = token.getBytes();
        final Deflater deflater = new Deflater();
        deflater.setInput(input);
        deflater.finish();

        final byte[] buffer = new byte[1024];
        byte[] output = new byte[1024];
        int start = 0;
        int copied;
        while ((copied = deflater.deflate(buffer)) == buffer.length) {
            output = writeBytesFromBuffer(buffer, output, start, copied);
            start += copied;
        }
        output = writeBytesFromBuffer(buffer, output, start, copied);
        start += copied;

        return Arrays.copyOf(output, start);
    }

    private byte[] decrypt(String input) {
        return encryptor.decrypt(Base64.getDecoder().decode(input));
    }

    String decompressToken(byte[] input) throws DataFormatException {
        final Inflater inflater = new Inflater();
        inflater.setInput(input);
        inflater.finished();

        final byte[] buffer = new byte[1024];
        byte[] output = new byte[1024];
        int start = 0;
        int copied;
        while ((copied = inflater.inflate(buffer)) == buffer.length) {
            output = writeBytesFromBuffer(buffer, output, start, copied);
            start += copied;
        }
        output = writeBytesFromBuffer(buffer, output, start, copied);
        start += copied;

        return new String(Arrays.copyOf(output, start));
    }

    private byte[] writeBytesFromBuffer(byte[] buffer, byte[] output, int start, int copied) {
        final byte[] newOutput;
        if (output.length - start > buffer.length) {
            newOutput = output;
        } else {
            newOutput = Arrays.copyOf(output, output.length * 2);
        }
        appendBufferToTarget(buffer, copied, start, newOutput);
        return newOutput;
    }

    private void appendBufferToTarget(byte[] buffer, int length, int start, byte[] target) {
        for (int i = 0; i < length; i++) {
            target[start + i] = buffer[i];
        }
    }

    public ResponseCookie packageToken(String token, CookieName audience) {
        return packageToken(token, null, audience);
    }

    /**
     * Produces a cookie that, when set for the given hostname, clears the corresponding security authorization.
     *
     * @param cookieHost The host the returned cookie should target. Should usually point to this DDAP server, and
     *                   should match the cookieHost passed to {@link #packageToken(String, CookieName)} on a previous request.
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
        default boolean encoded() {
            return true;
        }
    }

    @lombok.Value
    public static class OAuthTokenCookie implements CookieName {
        private final ServiceName serviceIdentifier;
        private final TokenKind tokenKind;

        @Override
        public String cookieName() {
            return serviceIdentifier.toString() + "_" + tokenKind.toString();
        }

        @Override
        public boolean encoded() {
            return !TokenKind.OAUTH_STATE.equals(tokenKind);
        }
    }

    /**
     * Marker interface for service names used in {@link CookieName}.
     */
    public interface ServiceName {
    }

    public enum BasicServices implements ServiceName {
        DAM, IC;

        public CookieName cookieName(TokenKind tokenKind) {
            return new OAuthTokenCookie(this, tokenKind);
        }

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    public enum TokenKind {
        ACCESS,
        IDENTITY,
        REFRESH,
        OAUTH_STATE;

        @Override
        public String toString() {
            return super.toString().toLowerCase();
        }
    }

    @RequiredArgsConstructor
    @Getter
    @ToString(exclude = "clearText")
    @EqualsAndHashCode(exclude = "clearText")
    public static class CookieValue {
        private final String cipherText;
        private final String clearText;
    }

}
