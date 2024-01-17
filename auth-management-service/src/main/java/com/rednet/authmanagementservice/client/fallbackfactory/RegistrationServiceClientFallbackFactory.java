package com.rednet.authmanagementservice.client.fallbackfactory;

import com.rednet.authmanagementservice.client.RegistrationServiceClient;
import org.springframework.cloud.openfeign.FallbackFactory;

public class RegistrationServiceClientFallbackFactory implements FallbackFactory<RegistrationServiceClient> {
    @Override
    public RegistrationServiceClient create(Throwable cause) {
        return null;
    }
}
