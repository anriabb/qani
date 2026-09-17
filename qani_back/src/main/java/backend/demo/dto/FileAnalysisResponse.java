package backend.demo.dto;

import java.time.LocalDateTime;
import java.util.List;

public class FileAnalysisResponse {

    private String query;
    private String hashTypeDetected;
    private String fileExtension;
    private boolean isExecutable;
    private int threatScore;
    private String threatLevel;
    private List<String> detectedRiskFactors;
    private LocalDateTime scannedAt;

    public FileAnalysisResponse(String query, String hashTypeDetected, String fileExtension,
                                boolean isExecutable, int threatScore, String threatLevel,
                                List<String> detectedRiskFactors, LocalDateTime scannedAt) {
        this.query = query;
        this.hashTypeDetected = hashTypeDetected;
        this.fileExtension = fileExtension;
        this.isExecutable = isExecutable;
        this.threatScore = threatScore;
        this.threatLevel = threatLevel;
        this.detectedRiskFactors = detectedRiskFactors;
        this.scannedAt = scannedAt;
    }

    public String getQuery() { return query; }
    public String getHashTypeDetected() { return hashTypeDetected; }
    public String getFileExtension() { return fileExtension; }
    public boolean isExecutable() { return isExecutable; }
    public int getThreatScore() { return threatScore; }
    public String getThreatLevel() { return threatLevel; }
    public List<String> getDetectedRiskFactors() { return detectedRiskFactors; }
    public LocalDateTime getScannedAt() { return scannedAt; }
}