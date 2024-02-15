package com.rednet.authmanagementservice.client;

import com.rednet.authmanagementservice.client.fallbackfactory.RegistrationServiceClientFallbackFactory;
import com.rednet.authmanagementservice.entity.Registration;
import com.rednet.authmanagementservice.model.RegistrationCreationData;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@FeignClient(name = "REGISTRATION-SERVICE",
             path = "/registrations",
             fallbackFactory = RegistrationServiceClientFallbackFactory.class)
public interface RegistrationServiceClient {
    @PostMapping(consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    ResponseEntity<Registration> createRegistration(@RequestBody RegistrationCreationData data);

    @GetMapping(path = "/by-id", produces = APPLICATION_JSON_VALUE)
    ResponseEntity<Registration> getRegistrationByID(@RequestParam("id") String ID);

    @PutMapping(consumes = APPLICATION_JSON_VALUE)
    ResponseEntity<Void> updateRegistration(@RequestBody Registration registration);

    @DeleteMapping("/by-id")
    ResponseEntity<Void> deleteRegistrationByID(@RequestParam("id") String ID);
}
