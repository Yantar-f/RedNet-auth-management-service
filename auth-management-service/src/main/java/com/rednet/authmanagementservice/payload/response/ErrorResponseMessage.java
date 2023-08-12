package com.rednet.authmanagementservice.payload.response;

import java.util.Date;
import java.util.List;

public class ErrorResponseMessage {
    private final String status;
    private final String timestamp;
    private final String path;
    private final List<String> messages;

    public ErrorResponseMessage(
        String status,
        String timestamp,
        String path,
        List<String> messages
    ) {
        this.status = status;
        this.timestamp = timestamp;
        this.path = path;
        this.messages = messages;
    }

    public String getStatus() {
        return status;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getPath() {
        return path;
    }

    public List<String> getMessages() {
        return messages;
    }
}

