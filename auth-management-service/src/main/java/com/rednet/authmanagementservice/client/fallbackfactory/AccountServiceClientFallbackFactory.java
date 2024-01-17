package com.rednet.authmanagementservice.client.fallbackfactory;

import com.rednet.authmanagementservice.client.AccountServiceClient;
import org.springframework.cloud.openfeign.FallbackFactory;

public class AccountServiceClientFallbackFactory implements FallbackFactory<AccountServiceClient> {
    @Override
    public AccountServiceClient create(Throwable cause) {
        return null;
    }
}
