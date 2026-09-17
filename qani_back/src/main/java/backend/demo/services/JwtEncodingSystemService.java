package backend.demo.services;

import backend.demo.dto.JwtDecodingSystemResponse;
import backend.demo.dto.JwtEncodingSystemRequest;
import backend.demo.dto.JwtEncodingSystemResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

@Service
public class JwtEncodingSystemService {

    private final ObjectMapper mapper = new ObjectMapper();
    private static final String DEFAULT_SECRET = "super_secret_jwt_key_that_is_at_least_32_bytes_long!";

    public JwtEncodingSystemResponse generateToken(JwtEncodingSystemRequest request) {
        try {
            String secret = (request.getSecretKey() != null && !request.getSecretKey().trim().isEmpty())
                    ? request.getSecretKey()
                    : DEFAULT_SECRET;

            long nowMillis = System.currentTimeMillis();
            long expMillis = nowMillis + (request.getExpirationMinutes() * 60 * 1000);

            // 1. Build Header JSON
            Map<String, Object> headerMap = new LinkedHashMap<>();
            headerMap.put("alg", "HS256");
            headerMap.put("typ", "JWT");

            // 2. Build Payload JSON
            Map<String, Object> payloadMap = new LinkedHashMap<>();
            if (request.getIssuer() != null) payloadMap.put("iss", request.getIssuer());
            if (request.getSubject() != null) payloadMap.put("sub", request.getSubject());
            payloadMap.put("iat", nowMillis / 1000);
            payloadMap.put("exp", expMillis / 1000);

            if (request.getCustomClaims() != null) {
                payloadMap.putAll(request.getCustomClaims());
            }

            // 3. Base64Url Encode Parts
            String encodedHeader = base64UrlEncode(mapper.writeValueAsString(headerMap).getBytes(StandardCharsets.UTF_8));
            String encodedPayload = base64UrlEncode(mapper.writeValueAsString(payloadMap).getBytes(StandardCharsets.UTF_8));

            // 4. Sign Header + Payload
            String dataToSign = encodedHeader + "." + encodedPayload;
            String signature = hmacSha256(dataToSign, secret);

            String token = dataToSign + "." + signature;

            LocalDateTime issuedAt = LocalDateTime.ofInstant(Instant.ofEpochMilli(nowMillis), ZoneId.systemDefault());
            LocalDateTime expiresAt = LocalDateTime.ofInstant(Instant.ofEpochMilli(expMillis), ZoneId.systemDefault());

            return new JwtEncodingSystemResponse(token, "HS256", issuedAt, expiresAt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode JWT: " + e.getMessage(), e);
        }
    }

    public JwtDecodingSystemResponse decodeToken(String token, String secretKey) {
        try {
            String[] parts = token.trim().split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid JWT structure. Must contain at least header and payload.");
            }

            String headerJson = new String(base64UrlDecode(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(base64UrlDecode(parts[1]), StandardCharsets.UTF_8);
            String signature = parts.length > 2 ? parts[2] : "";

            Map<String, Object> header = mapper.readValue(headerJson, new TypeReference<>() {});
            Map<String, Object> payload = mapper.readValue(payloadJson, new TypeReference<>() {});

            // Validate Expiration
            boolean isExpired = false;
            if (payload.containsKey("exp")) {
                long exp = ((Number) payload.get("exp")).longValue();
                isExpired = (System.currentTimeMillis() / 1000) > exp;
            }

            // Validate Signature
            boolean isSignatureValid = false;
            if (!signature.isEmpty()) {
                String secret = (secretKey != null && !secretKey.trim().isEmpty()) ? secretKey : DEFAULT_SECRET;
                String expectedSignature = hmacSha256(parts[0] + "." + parts[1], secret);
                isSignatureValid = constantTimeEquals(signature, expectedSignature);
            }

            return new JwtDecodingSystemResponse(header, payload, signature, isSignatureValid, isExpired);
        } catch (Exception e) {
            return new JwtDecodingSystemResponse(
                    Collections.singletonMap("error", "Malformed Token"),
                    Collections.singletonMap("details", e.getMessage()),
                    "", false, true
            );
        }
    }

    private String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private byte[] base64UrlDecode(String str) {
        return Base64.getUrlDecoder().decode(str);
    }

    private String hmacSha256(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return base64UrlEncode(rawHmac);
    }

    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}