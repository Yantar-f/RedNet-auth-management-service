package com.rednet.authmanagementservice.config;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import static org.springframework.http.HttpHeaders.COOKIE;

@Component
public class SecurityRequestInterceptor implements RequestInterceptor {
    private final ApiTokenConfig apiTokenConfig;

    public SecurityRequestInterceptor(ApiTokenConfig apiTokenConfig) {
        this.apiTokenConfig = apiTokenConfig;
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {
        String apiToken = extractApiTokenFromContext();
        String apiTokenCookie = createApiTokenCookie(apiTokenConfig, apiToken);

        requestTemplate.header(COOKIE, apiTokenCookie);
    }

    private String createApiTokenCookie(ApiTokenConfig config, String token) {
        return new HttpCookie(config.getCookieName(), token).toString();
    }

    private String extractApiTokenFromContext() {
        return (String) SecurityContextHolder.getContext().getAuthentication().getCredentials();
    }
}
