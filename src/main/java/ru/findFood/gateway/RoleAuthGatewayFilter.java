package ru.findFood.gateway;

import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
public class RoleAuthGatewayFilter extends AbstractGatewayFilterFactory<RoleAuthGatewayFilter.Config> {
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public GatewayFilter apply(RoleAuthGatewayFilter.Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            if(!jwtUtil.hasRole(request, config.getRole())){
                return this.onError(exchange, "Not enough rights", HttpStatus.FORBIDDEN);
            }
            return chain.filter(exchange);
        };
    }

    private void populateRequestWithHeaders(ServerWebExchange exchange, String token) {
        Claims claims = jwtUtil.getAllClaimsFromToken(token);
        exchange.getRequest().mutate()
                .header("username", claims.getSubject())
                .header("role", String.valueOf(claims.get("role")))
                .build();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    public RoleAuthGatewayFilter() {
        super(RoleAuthGatewayFilter.Config.class);
    }

    public static class Config {
        private String role;

        public String getRole() {
            return role;
        }
    }
}
