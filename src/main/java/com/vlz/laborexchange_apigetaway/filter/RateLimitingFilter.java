package com.vlz.laborexchange_apigetaway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

@Component
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private static final int MAX_REQUESTS = 100;
    private static final int AUTH_MAX_REQUESTS = 20;
    private static final long WINDOW_SECONDS = 60L;

    // Lua script for atomic sliding window counter using Redis
    private static final String RATE_LIMIT_SCRIPT =
        "local key = KEYS[1] " +
        "local limit = tonumber(ARGV[1]) " +
        "local window = tonumber(ARGV[2]) " +
        "local current = redis.call('INCR', key) " +
        "if current == 1 then " +
        "  redis.call('EXPIRE', key, window) " +
        "end " +
        "return current";

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RedisScript<Long> rateLimitScript;

    public RateLimitingFilter(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.rateLimitScript = RedisScript.of(RATE_LIMIT_SCRIPT, Long.class);
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String clientIp = getClientIp(exchange);
        String path = exchange.getRequest().getPath().value();

        // WebSocket/SockJS paths use persistent connections — exclude from per-request rate limiting
        if (path.startsWith("/ws-chat/")) {
            return chain.filter(exchange);
        }

        boolean isAuthPath = path.startsWith("/api/auth/");
        int limit = isAuthPath ? AUTH_MAX_REQUESTS : MAX_REQUESTS;
        String key = "rate_limit:" + clientIp + ":" + (isAuthPath ? "auth" : "general");

        return redisTemplate.execute(rateLimitScript, List.of(key),
                List.of(String.valueOf(limit), String.valueOf(WINDOW_SECONDS)))
            .next()
            .flatMap(count -> {
                int remaining = Math.max(0, limit - count.intValue());
                exchange.getResponse().getHeaders().add("X-RateLimit-Limit", String.valueOf(limit));
                exchange.getResponse().getHeaders().add("X-RateLimit-Remaining", String.valueOf(remaining));

                if (count > limit) {
                    log.warn("Rate limit exceeded for IP: {} on path: {}", clientIp, path);
                    exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                    return exchange.getResponse().setComplete();
                }
                return chain.filter(exchange);
            })
            .onErrorResume(e -> {
                // If Redis is unavailable, allow the request (fail open)
                log.error("Redis rate limiting error, failing open: {}", e.getMessage());
                return chain.filter(exchange);
            });
    }

    private static final List<String> TRUSTED_PROXY_PREFIXES = List.of(
            "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168."
    );

    private String getClientIp(ServerWebExchange exchange) {
        var address = exchange.getRequest().getRemoteAddress();
        String remoteIp = address != null ? address.getAddress().getHostAddress() : "unknown";
        // Only trust X-Forwarded-For when the TCP connection comes from a known internal proxy
        boolean isTrustedProxy = TRUSTED_PROXY_PREFIXES.stream().anyMatch(remoteIp::startsWith);
        if (isTrustedProxy) {
            String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }
        }
        return remoteIp;
    }

    @Override
    public int getOrder() {
        // Must run BEFORE JwtAuthenticationFilter (order -10) to rate-limit before auth processing
        return -11;
    }
}
