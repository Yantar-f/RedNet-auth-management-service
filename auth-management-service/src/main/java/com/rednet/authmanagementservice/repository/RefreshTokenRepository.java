package com.rednet.authmanagementservice.repository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class RefreshTokenRepository {
    private final RedisTemplate<String, String> template;
    private final long tokenExpirationMs;
    public RefreshTokenRepository(
        @Qualifier("refreshTokenRedisTemplate") RedisTemplate<String, String> template,
        @Value("${rednet.app.refresh-token-expiration-ms}") long tokenExpirationMs
    ) {
        this.template = template;
        this.tokenExpirationMs = tokenExpirationMs;
    }

    public void save(String userID, String token) {
        template.opsForValue().set(userID, token, tokenExpirationMs, TimeUnit.MILLISECONDS);
    }

    public String find(String userID) {
        return template.opsForValue().get(userID);
    }
}
