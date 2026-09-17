package backend.demo.dto;

import java.time.LocalDateTime;
import java.util.List;

public class UrlAnalysisResponse {

    private String urlHash;
    private String url;
    private String domain;
    private boolean usesHttps;
    private boolean containsIpAddress;
    private int subdomainCount;
    private int threatScore;
    private String threatLevel;
    private List<String> detectedRiskFactors;
    private LocalDateTime scannedAt;

    public UrlAnalysisResponse(String urlHash, String url, String domain, boolean usesHttps,
                               boolean containsIpAddress, int subdomainCount, int threatScore,
                               String threatLevel, List<String> detectedRiskFactors, LocalDateTime scannedAt) {
        this.urlHash = urlHash;
        this.url = url;
        this.domain = domain;
        this.usesHttps = usesHttps;
        this.containsIpAddress = containsIpAddress;
        this.subdomainCount = subdomainCount;
        this.threatScore = threatScore;
        this.threatLevel = threatLevel;
        this.detectedRiskFactors = detectedRiskFactors;
        this.scannedAt = scannedAt;
    }

    public String getUrlHash() { return urlHash; }
    public String getUrl() { return url; }
    public String getDomain() { return domain; }
    public boolean isUsesHttps() { return usesHttps; }
    public boolean isContainsIpAddress() { return containsIpAddress; }
    public int getSubdomainCount() { return subdomainCount; }
    public int getThreatScore() { return threatScore; }
    public String getThreatLevel() { return threatLevel; }
    public List<String> getDetectedRiskFactors() { return detectedRiskFactors; }
    public LocalDateTime getScannedAt() { return scannedAt; }
}