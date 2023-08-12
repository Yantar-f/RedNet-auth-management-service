package com.rednet.authmanagementservice.config;

import com.rednet.authmanagementservice.entity.Registration;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {
    private final String refreshTokenRedisHost;
    private final int refreshTokenRedisPort;
    private final String registrationRedisHost;
    private final int registrationRedisPort;

    public RedisConfig(
        @Value("${spring.data.redis.refresh-token-db.host}") String refreshTokenRedisHost,
        @Value("${spring.data.redis.refresh-token-db.port}") int refreshTokenRedisPort,
        @Value("${spring.data.redis.registration-db.host}") String registrationRedisHost,
        @Value("${spring.data.redis.registration-db.port}") int registrationRedisPort
    ) {
        this.refreshTokenRedisHost = refreshTokenRedisHost;
        this.refreshTokenRedisPort = refreshTokenRedisPort;
        this.registrationRedisHost = registrationRedisHost;
        this.registrationRedisPort = registrationRedisPort;
    }

    @Bean
    @Qualifier("refreshTokenRedisFactory")
    public LettuceConnectionFactory refreshTokenRedisFactory() {
        return new LettuceConnectionFactory(
            new RedisStandaloneConfiguration(refreshTokenRedisHost,refreshTokenRedisPort)
        );
    }

    @Bean
    @Qualifier("registrationRedisFactory")
    public LettuceConnectionFactory activationCodeRedisFactory() {
        return new LettuceConnectionFactory(
            new RedisStandaloneConfiguration(registrationRedisHost,registrationRedisPort)
        );
    }

    @Bean
    @Qualifier("refreshTokenRedisTemplate")
    public RedisTemplate<String,String> refreshTokenRedisTemplate(
        @Qualifier("refreshTokenRedisFactory") LettuceConnectionFactory refreshTokenRedisFactory
    ) {
        RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(refreshTokenRedisFactory);
        redisTemplate.setDefaultSerializer(new StringRedisSerializer());
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    @Bean
    @Qualifier("registrationRedisTemplate")
    public RedisTemplate<String, Registration> activationCodeRedisTemplate(
        @Qualifier("registrationRedisFactory") LettuceConnectionFactory registrationRedisFactory
    ) {
        RedisTemplate<String, Registration> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(registrationRedisFactory);
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(Registration.class));
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }
}
