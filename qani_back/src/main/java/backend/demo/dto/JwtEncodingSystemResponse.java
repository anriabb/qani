package backend.demo.dto;

import java.time.LocalDateTime;

public class JwtEncodingSystemResponse {

    private String token;
    private String algorithm;
    private LocalDateTime issuedAt;
    private LocalDateTime expiresAt;

    public JwtEncodingSystemResponse(String token, String algorithm, LocalDateTime issuedAt, LocalDateTime expiresAt) {
        this.token = token;
        this.algorithm = algorithm;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getToken() { return token; }
    public String getAlgorithm() { return algorithm; }
    public LocalDateTime getIssuedAt() { return issuedAt; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
}