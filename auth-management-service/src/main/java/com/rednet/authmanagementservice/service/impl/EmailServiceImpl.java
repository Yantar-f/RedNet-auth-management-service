package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.service.EmailService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender emailSender;
    private final String sender;

    public EmailServiceImpl(JavaMailSender emailSender,
                            @Value("${spring.mail.username}") String sender) {
        this.emailSender = emailSender;
        this.sender = sender;
    }

    @Override
    public void sendRegistrationActivationMessage(String receiverEmail, String activationCode) {
        SimpleMailMessage message = new SimpleMailMessage();

        message.setFrom(sender);
        message.setTo(receiverEmail);
        message.setSubject("RedNet registration");
        message.setText(generateText(activationCode));

        emailSender.send(message);
    }

    private String generateText(String verificationToken){
        return "Email verification code: " + verificationToken;
    }
}
