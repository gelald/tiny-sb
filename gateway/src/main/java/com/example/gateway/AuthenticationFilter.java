package com.example.gateway;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final WebClient webClient = WebClient.builder().build();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        URI uri = exchange.getRequest().getURI();
        String path = uri.getPath();

        // Whitelist auth endpoints and actuator
        if (path.startsWith("/api/auth/") || path.startsWith("/actuator")) {
            log.info("Whitelisted endpoint: {}", path);
            return chain.filter(exchange);
        }

        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("JSESSIONID");
        if (cookie == null) {
            log.info("No cookie found, redirecting to login page");
            String redirectTarget = uri.getRawPath() + (uri.getRawQuery() != null ? ("?" + uri.getRawQuery()) : "");
            String location = "/api/auth/login-page?redirect="
                    + java.net.URLEncoder.encode(redirectTarget, java.nio.charset.StandardCharsets.UTF_8);
            log.info("Redirecting to login page: {}", location);
            exchange.getResponse().setStatusCode(HttpStatus.FOUND);
            exchange.getResponse().getHeaders().set("Location", location);
            return exchange.getResponse().setComplete();
        }

        log.info("Validating cookie: {}", cookie.getValue());
        // Call auth-service /auth/validate with the same cookie
        return webClient.get()
                .uri("http://localhost:18083/auth/validate")
                .cookie("JSESSIONID", cookie.getValue())
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return chain.filter(exchange);
                    }
                    log.info("Invalid cookie, redirecting to login page");
                    String redirectTarget = uri.getRawPath()
                            + (uri.getRawQuery() != null ? ("?" + uri.getRawQuery()) : "");
                    String location = "/api/auth/login-page?redirect="
                            + java.net.URLEncoder.encode(redirectTarget, java.nio.charset.StandardCharsets.UTF_8);
                    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                    exchange.getResponse().getHeaders().set("Location", location);
                    return exchange.getResponse().setComplete();
                });
    }

    @Override
    public int getOrder() {
        return -100; // run early
    }
}
