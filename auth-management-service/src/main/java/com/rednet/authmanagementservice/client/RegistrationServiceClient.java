package com.rednet.authmanagementservice.client;

import com.rednet.authmanagementservice.client.fallbackfactory.RegistrationServiceClientFallbackFactory;
import org.springframework.cloud.openfeign.FeignClient;

@FeignClient(
        name = "REGISTRATION_SERVICE",
        path = "/registrations",
        fallbackFactory = RegistrationServiceClientFallbackFactory.class)
public interface RegistrationServiceClient {
}
