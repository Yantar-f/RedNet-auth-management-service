package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.util.ActivationCodeGenerator;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component
public class ActivationCodeGeneratorImpl implements ActivationCodeGenerator {
    private final int rangeMin = 100000;
    private final int rangeMax = 1000000;
    private final Random activationCodeRandom = new Random();
    @Override
    public String generate() {
        return String.valueOf(activationCodeRandom.nextInt(rangeMax - rangeMin) + rangeMin);
    }
}
