package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.service.ActivationCodeGenerator;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component
public class ActivationCodeGeneratorImpl implements ActivationCodeGenerator {
    private final int activationCodeMin = 100000;
    private final int activationCodeMax = 1000000;
    private final Random activationCodeRandom = new Random();
    @Override
    public int generate() {
        return activationCodeRandom.nextInt(activationCodeMax - activationCodeMin) + activationCodeMin;
    }
}
