package com.rednet.authmanagementservice.config;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import static org.springframework.http.HttpHeaders.COOKIE;

@Component
public class SecurityRequestInterceptor implements RequestInterceptor {
    private final String apiTokenCookieName;

    public SecurityRequestInterceptor(@Value("${rednet.app.security.api-token.cookie-name}") String apiTokenCookieName) {
        this.apiTokenCookieName = apiTokenCookieName;
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {
        HttpCookie apiTokenCookie = new HttpCookie(
            apiTokenCookieName,
            (String) SecurityContextHolder.getContext().getAuthentication().getCredentials()
        );

        requestTemplate.header(COOKIE, apiTokenCookie.toString());
    }
}
