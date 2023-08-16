package com.rednet.authmanagementservice.service.impl;

import com.rednet.authmanagementservice.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    private final JavaMailSender emailSender;
    private final String sender;

    public EmailServiceImpl(
        JavaMailSender emailSender,
        @Value("${spring.mail.username}") String sender
    ) {
        this.emailSender = emailSender;
        this.sender = sender;
    }

    @Async
    @Override
    public void sendRegistrationActivationMessage(String receiverEmail, String activationCode) {
        try{
            MimeMessage mimeMessage = emailSender.createMimeMessage();
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage);

            mimeMessageHelper.setFrom(sender);
            mimeMessageHelper.setTo(receiverEmail);
            mimeMessageHelper.setSubject("RedNet registration");
            mimeMessageHelper.setText(generateText(activationCode));

            emailSender.send(mimeMessage);
        } catch(MessagingException ex) {
            throw new IllegalStateException("failed to send message");
        }
    }

    private String generateText(String verificationToken){
        return "Email verification code: " + verificationToken;
    }
}
