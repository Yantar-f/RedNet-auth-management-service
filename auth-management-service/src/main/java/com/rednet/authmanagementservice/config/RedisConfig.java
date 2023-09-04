package com.rednet.authmanagementservice.config;

import com.rednet.authmanagementservice.entity.Registration;
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
    private final String registrationRedisHost;
    private final int registrationRedisPort;

    public RedisConfig(
        @Value("${spring.data.redis.host}") String registrationRedisHost,
        @Value("${spring.data.redis.port}") int registrationRedisPort
    ) {
        this.registrationRedisHost = registrationRedisHost;
        this.registrationRedisPort = registrationRedisPort;
    }

    @Bean
    public LettuceConnectionFactory registrationRedisFactory() {
        return new LettuceConnectionFactory(
            new RedisStandaloneConfiguration(registrationRedisHost,registrationRedisPort)
        );
    }

    @Bean
    public RedisTemplate<String, Registration> registrationRedisTemplate() {
        RedisTemplate<String, Registration> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(registrationRedisFactory());
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new Jackson2JsonRedisSerializer<>(Registration.class));
        redisTemplate.setHashValueSerializer(new Jackson2JsonRedisSerializer<>(Registration.class));
        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }
}
