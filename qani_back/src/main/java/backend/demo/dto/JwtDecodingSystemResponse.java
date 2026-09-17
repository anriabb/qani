package backend.demo.dto;

import java.util.Map;

public class JwtDecodingSystemResponse {

    private Map<String, Object> header;
    private Map<String, Object> payload;
    private String signature;
    private boolean isSignatureValid;
    private boolean isExpired;

    public JwtDecodingSystemResponse(Map<String, Object> header, Map<String, Object> payload,
                                     String signature, boolean isSignatureValid, boolean isExpired) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.isSignatureValid = isSignatureValid;
        this.isExpired = isExpired;
    }

    public Map<String, Object> getHeader() { return header; }
    public Map<String, Object> getPayload() { return payload; }
    public String getSignature() { return signature; }
    public boolean isSignatureValid() { return isSignatureValid; }
    public boolean isExpired() { return isExpired; }
}