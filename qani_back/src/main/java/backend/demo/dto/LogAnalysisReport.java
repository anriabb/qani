package backend.demo.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class LogAnalysisReport {

    private String fileName;
    private long fileSize;
    private int totalLines;
    private Map<String, Integer> logLevelCounts;
    private Map<String, Integer> topErrorMessages;
    private List<String> securityAlerts;
    private List<String> recentErrors;
    private LocalDateTime analyzedAt;

    public LogAnalysisReport(String fileName, long fileSize, int totalLines,
                             Map<String, Integer> logLevelCounts,
                             Map<String, Integer> topErrorMessages,
                             List<String> securityAlerts,
                             List<String> recentErrors,
                             LocalDateTime analyzedAt) {
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.totalLines = totalLines;
        this.logLevelCounts = logLevelCounts;
        this.topErrorMessages = topErrorMessages;
        this.securityAlerts = securityAlerts;
        this.recentErrors = recentErrors;
        this.analyzedAt = analyzedAt;
    }

    public String getFileName() { return fileName; }
    public long getFileSize() { return fileSize; }
    public int getTotalLines() { return totalLines; }
    public Map<String, Integer> getLogLevelCounts() { return logLevelCounts; }
    public Map<String, Integer> getTopErrorMessages() { return topErrorMessages; }
    public List<String> getSecurityAlerts() { return securityAlerts; }
    public List<String> getRecentErrors() { return recentErrors; }
    public LocalDateTime getAnalyzedAt() { return analyzedAt; }
}