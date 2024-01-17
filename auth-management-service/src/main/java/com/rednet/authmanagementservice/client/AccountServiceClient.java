package com.rednet.authmanagementservice.client;

import com.rednet.authmanagementservice.client.fallbackfactory.AccountServiceClientFallbackFactory;
import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(
        name = "ACCOUNT_SERVICE",
        path = "/accounts",
        fallbackFactory = AccountServiceClientFallbackFactory.class)
public interface AccountServiceClient {

}
