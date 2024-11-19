package se.digg.eudiw.credentialissuer.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

public record SelectiveDisclosure(String salt, String name, Object value) {
    public SelectiveDisclosure(String name, Object value) {
        this(generateSalt(), name, value);
    }

    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public String content() {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.writeValueAsString(List.of(salt, name, value));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String disclosure() {
        return Base64.getEncoder().encodeToString(content().replace(",", ", ").replace(":", ": ").getBytes()).replace("=", "");
    }

    public String hash() {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedhash = digest.digest(
                disclosure().getBytes(StandardCharsets.UTF_8)
            );
            return Base64.getEncoder().encodeToString(encodedhash).replace("=", "");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
