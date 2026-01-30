package com.vlz.laborexchange_apigetaway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.List;

@Component
@Slf4j
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secret;

    private static final List<String> EXCLUDED_URLS = List.of(
            "/api/auth/register",
            "/api/auth/login"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();
        long startTime = System.currentTimeMillis();

        log.debug("Request ID: {} | Method: {} | Path: {}", request.getId(), request.getMethod(), path);

        if (HttpMethod.OPTIONS.equals(request.getMethod())) {
            return chain.filter(exchange);
        }

        boolean isExcluded = EXCLUDED_URLS.stream().anyMatch(path::contains);
        if (isExcluded) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        try {
            Key key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key).build()
                    .parseClaimsJws(token).getBody();

            String userId = claims.getSubject();
            String role = claims.get("role", String.class);

            if (path.startsWith("/api/vacancies") && HttpMethod.POST.equals(request.getMethod())) {
                if (!"EMPLOYER".equals(role)) {
                    log.warn("Access Denied: User {} with role {} tried to create vacancy", userId, role);
                    return onError(exchange, "Access denied: Employers only", HttpStatus.FORBIDDEN);
                }
            }

            ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(r -> r.header("X-User-Id", userId)
                            .header("X-User-Role", role))
                    .build();

            return chain.filter(modifiedExchange).then(Mono.fromRunnable(() -> {
                log.info("Path: {} | Status: {} | Time: {}ms",
                        path, exchange.getResponse().getStatusCode(), (System.currentTimeMillis() - startTime));
            }));

        } catch (Exception e) {
            log.error("JWT Error: {}", e.getMessage());
            return onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus status) {
        log.error("Error Filter: {} - Status: {}", err, status);
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -10;
    }
}