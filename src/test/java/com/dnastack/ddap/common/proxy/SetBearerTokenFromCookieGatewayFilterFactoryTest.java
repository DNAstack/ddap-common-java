package com.dnastack.ddap.common.proxy;

import com.dnastack.ddap.common.TokenEncryptorFactory;
import com.dnastack.ddap.common.proxy.SetBearerTokenFromCookieGatewayFilterFactory.Service;
import com.dnastack.ddap.common.security.UserTokenCookiePackager;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.BasicServices;
import com.dnastack.ddap.common.security.UserTokenCookiePackager.TokenKind;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.server.ServerWebExchange;

import java.net.URI;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@SuppressWarnings("UnassignedFluxMonoInstance")
@RunWith(SpringRunner.class)
@SpringBootTest(classes = { TokenEncryptorFactory.class, UserTokenCookiePackager.class })
public class SetBearerTokenFromCookieGatewayFilterFactoryTest {

    @Autowired
    private UserTokenCookiePackager cookiePackager;
    GatewayFilter filter;

    @Before
    public void setUp() {
        SetBearerTokenFromCookieGatewayFilterFactory filterFactory = new SetBearerTokenFromCookieGatewayFilterFactory(cookiePackager);
        SetBearerTokenFromCookieGatewayFilterFactory.Config config = new SetBearerTokenFromCookieGatewayFilterFactory.Config();
        config.setService(Service.IC);
        config.setTokenKind(TokenKind.IDENTITY);
        filter = filterFactory.apply(config);
    }

    @Test
    public void shouldCopyUserTokenCookieAsBearerTokenInOnwardRequest() {
        // given
        String cookieToken = "attach this as a bearer token and everyone's happy!";
        URI originalUri = URI.create("http://example.com/anything");

        ServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.get("http://example.com/anything")
                .cookie(new HttpCookie(BasicServices.IC.cookieName(TokenKind.IDENTITY).cookieName(), cookiePackager.encodeToken(cookieToken)))
                .build());

        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        // when
        filter.filter(exchange, chain);

        // then
        ArgumentCaptor<ServerWebExchange> result = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(result.capture());
        ServerHttpRequest onwardRequest = result.getValue().getRequest();
        assertThat(onwardRequest.getURI(), is(originalUri));
        assertThat(onwardRequest.getHeaders().getFirst("Authorization"), is("Bearer " + cookieToken));
    }

    @Test
    public void shouldPassThroughRequestsWithoutCookie() {
        // given
        URI originalUri = URI.create("http://example.com/anything");

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get(originalUri.toString()).build());

        GatewayFilterChain chain = mock(GatewayFilterChain.class);

        // when
        filter.filter(exchange, chain);

        // then
        ArgumentCaptor<ServerWebExchange> result = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(result.capture());
        URI onwardRequestUri = result.getValue().getRequest().getURI();
        assertThat(onwardRequestUri, is(originalUri));
    }

}
