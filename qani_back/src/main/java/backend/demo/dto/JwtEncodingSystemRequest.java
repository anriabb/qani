package backend.demo.dto;

import java.util.Map;

public class JwtEncodingSystemRequest {

    private String subject;
    private String issuer;
    private long expirationMinutes;
    private Map<String, Object> customClaims;
    private String secretKey;

    public JwtEncodingSystemRequest() {}

    public JwtEncodingSystemRequest(String subject, String issuer, long expirationMinutes,
                                    Map<String, Object> customClaims, String secretKey) {
        this.subject = subject;
        this.issuer = issuer;
        this.expirationMinutes = expirationMinutes;
        this.customClaims = customClaims;
        this.secretKey = secretKey;
    }

    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public long getExpirationMinutes() { return expirationMinutes; }
    public void setExpirationMinutes(long expirationMinutes) { this.expirationMinutes = expirationMinutes; }

    public Map<String, Object> getCustomClaims() { return customClaims; }
    public void setCustomClaims(Map<String, Object> customClaims) { this.customClaims = customClaims; }

    public String getSecretKey() { return secretKey; }
    public void setSecretKey(String secretKey) { this.secretKey = secretKey; }
}