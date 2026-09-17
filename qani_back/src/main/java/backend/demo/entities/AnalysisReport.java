package backend.demo.entities;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "file_analysis_reports")
public class AnalysisReport {

    @Id
    private String sha256;

    private String fileName;
    private String mimeType;
    private long fileSize;
    private String md5;
    private String sha1;

    private double entropy;
    private boolean headerMismatched;

    private int threatScore;
    private String threatLevel;

    @ElementCollection
    private List<String> matchedYaraRules;

    @ElementCollection
    private List<String> extractedSuspiciousStrings;

    private LocalDateTime scannedAt;

    // Default Constructor required by JPA
    public AnalysisReport() {}

    // Getters and Setters
    public String getSha256() { return sha256; }
    public void setSha256(String sha256) { this.sha256 = sha256; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }

    public String getMimeType() { return mimeType; }
    public void setMimeType(String mimeType) { this.mimeType = mimeType; }

    public long getFileSize() { return fileSize; }
    public void setFileSize(long fileSize) { this.fileSize = fileSize; }

    public String getMd5() { return md5; }
    public void setMd5(String md5) { this.md5 = md5; }

    public String getSha1() { return sha1; }
    public void setSha1(String sha1) { this.sha1 = sha1; }

    public double getEntropy() { return entropy; }
    public void setEntropy(double entropy) { this.entropy = entropy; }

    public boolean isHeaderMismatched() { return headerMismatched; }
    public void setHeaderMismatched(boolean headerMismatched) { this.headerMismatched = headerMismatched; }

    public int getThreatScore() { return threatScore; }
    public void setThreatScore(int threatScore) { this.threatScore = threatScore; }

    public String getThreatLevel() { return threatLevel; }
    public void setThreatLevel(String threatLevel) { this.threatLevel = threatLevel; }

    public List<String> getMatchedYaraRules() { return matchedYaraRules; }
    public void setMatchedYaraRules(List<String> matchedYaraRules) { this.matchedYaraRules = matchedYaraRules; }

    public List<String> getExtractedSuspiciousStrings() { return extractedSuspiciousStrings; }
    public void setExtractedSuspiciousStrings(List<String> extractedSuspiciousStrings) { this.extractedSuspiciousStrings = extractedSuspiciousStrings; }

    public LocalDateTime getScannedAt() { return scannedAt; }
    public void setScannedAt(LocalDateTime scannedAt) { this.scannedAt = scannedAt; }
}