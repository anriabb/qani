package backend.demo.dto;

import java.time.LocalDateTime;
import java.util.List;

public class HeaderAnalysisResponse {

    private String senderDomain;
    private String returnPathDomain;
    private String spfStatus;
    private String dkimStatus;
    private String dmarcStatus;
    private boolean isDomainAligned;
    private int totalHops;
    private int threatScore;
    private String threatLevel;
    private List<String> detectedRiskFactors;
    private LocalDateTime scannedAt;

    public HeaderAnalysisResponse(String senderDomain, String returnPathDomain, String spfStatus,
                                  String dkimStatus, String dmarcStatus, boolean isDomainAligned,
                                  int totalHops, int threatScore, String threatLevel,
                                  List<String> detectedRiskFactors, LocalDateTime scannedAt) {
        this.senderDomain = senderDomain;
        this.returnPathDomain = returnPathDomain;
        this.spfStatus = spfStatus;
        this.dkimStatus = dkimStatus;
        this.dmarcStatus = dmarcStatus;
        this.isDomainAligned = isDomainAligned;
        this.totalHops = totalHops;
        this.threatScore = threatScore;
        this.threatLevel = threatLevel;
        this.detectedRiskFactors = detectedRiskFactors;
        this.scannedAt = scannedAt;
    }

    public String getSenderDomain() { return senderDomain; }
    public String getReturnPathDomain() { return returnPathDomain; }
    public String getSpfStatus() { return spfStatus; }
    public String getDkimStatus() { return dkimStatus; }
    public String getDmarcStatus() { return dmarcStatus; }
    public boolean isDomainAligned() { return isDomainAligned; }
    public int getTotalHops() { return totalHops; }
    public int getThreatScore() { return threatScore; }
    public String getThreatLevel() { return threatLevel; }
    public List<String> getDetectedRiskFactors() { return detectedRiskFactors; }
    public LocalDateTime getScannedAt() { return scannedAt; }
}