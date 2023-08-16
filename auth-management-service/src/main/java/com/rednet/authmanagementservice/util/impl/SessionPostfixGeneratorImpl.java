package com.rednet.authmanagementservice.util.impl;

import com.rednet.authmanagementservice.util.SessionPostfixGenerator;
import org.springframework.stereotype.Component;

import java.util.Random;

@Component
public class SessionPostfixGeneratorImpl implements SessionPostfixGenerator {
    private final int rangeMin = 100000;
    private final int rangeMax = 1000000;
    private final Random random = new Random();
    @Override
    public String generate() {
        return String.valueOf(random.nextInt(rangeMax - rangeMin) + rangeMin);
    }
}
