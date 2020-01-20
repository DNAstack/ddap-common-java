package com.dnastack.ddap.common.security;

import com.dnastack.ddap.common.TokenEncryptorFactory;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import com.dnastack.ddap.common.security.filter.UserTokenStatusFilter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices.IC;
import static java.lang.String.format;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(classes = { TokenEncryptorFactory.class, UserTokenCookiePackager.class })
public class UserTokenStatusFilterTest {

    @Autowired
    private UserTokenCookiePackager cookiePackager;
    @MockBean
    private ServerWebExchange exchange;
    private UserTokenStatusFilter filter;

    @Before
    public void setUp() throws Exception {
        this.filter = new UserTokenStatusFilter(cookiePackager, IC.cookieName(TokenKind.IDENTITY));
    }

    @Test
    public void shouldTreatMalformedJwtAsExpired() {
        assertResponseExpiresCookie(cookiePackager.encodeToken("not_enough_sections"));
        assertResponseExpiresCookie(cookiePackager.encodeToken("not!.even!.base64!"));
        assertResponseExpiresCookie(cookiePackager.encodeToken("not.aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g_dj1vSGc1U0pZUkhBMA.json"));
    }

    @Test
    public void shouldNotRemoveValidJwtCookie() throws Exception {
        assertResponseLeavesCookieAlone(fakeUserToken(Instant.now().plusSeconds(10)));
    }

    @Test
    public void shouldPassThroughRequestsWithoutCookie() {
        // given
        URI originalUri = URI.create("http://example.com/anything");

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get(originalUri.toString()).build());

        WebFilterChain chain = mock(WebFilterChain.class);

        // when
        filter.filter(exchange, chain);

        // then
        ArgumentCaptor<ServerWebExchange> result = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(result.capture());
        URI onwardRequestUri = result.getValue().getRequest().getURI();
        assertThat(onwardRequestUri, is(originalUri));
    }

    private void assertResponseExpiresCookie(String jwtValue) {
        ResponseCookie responseCookie = runFilterAndExtractResponseCookie(jwtValue);
        assertThat(format("Expected a '%s' cookie in the response", IC.cookieName(TokenKind.IDENTITY).cookieName()), responseCookie, notNullValue());
        assertThat(responseCookie.getValue(), is("expired"));
        assertThat(responseCookie.getMaxAge(), is(Duration.ZERO));
    }

    private void assertResponseLeavesCookieAlone(String jwtValue) {
        ResponseCookie responseCookie = runFilterAndExtractResponseCookie(jwtValue);
        assertThat(responseCookie, nullValue());
    }

    private ResponseCookie runFilterAndExtractResponseCookie(String jwtValue) {
        // given
        ServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("http://example.com/anything")
                .cookie(new HttpCookie(IC.cookieName(TokenKind.IDENTITY).cookieName(), jwtValue)).build()
        );

        WebFilterChain chain = mock(WebFilterChain.class);

        // when
        filter.filter(exchange, chain);

        // then
        ArgumentCaptor<ServerWebExchange> result = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(result.capture());
        return result.getValue().getResponse().getCookies().getFirst(IC.cookieName(TokenKind.IDENTITY).cookieName());
    }

    private String fakeUserToken(Instant exp) throws JsonProcessingException {
        ObjectMapper jsonMapper = new ObjectMapper();
        Base64.Encoder b64Encoder = Base64.getUrlEncoder().withoutPadding();

        Map<String, Object> header = new HashMap<>();
        header.put("typ", "JWT");
        header.put("alg", "none");

        Map<String, Object> body = new HashMap<>();
        body.put("exp", exp.getEpochSecond());

        return cookiePackager.encodeToken(b64Encoder.encodeToString(jsonMapper.writeValueAsBytes(header)) +
                "." +
                b64Encoder.encodeToString(jsonMapper.writeValueAsBytes(body)) +
                ".");
    }
}
