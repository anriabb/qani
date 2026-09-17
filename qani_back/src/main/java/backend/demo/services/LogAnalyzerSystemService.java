package backend.demo.services;

import backend.demo.dto.LogAnalysisReport;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class LogAnalyzerSystemService {

    public LogAnalysisReport analyzeLogFile(MultipartFile file) {
        String fileName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "server.log";
        long fileSize = file.getSize();

        int totalLines = 0;
        Map<String, Integer> logLevelCounts = new HashMap<>();
        logLevelCounts.put("INFO", 0);
        logLevelCounts.put("WARN", 0);
        logLevelCounts.put("ERROR", 0);
        logLevelCounts.put("DEBUG", 0);
        logLevelCounts.put("OTHER", 0);

        Map<String, Integer> topErrorMessages = new LinkedHashMap<>();
        List<String> securityAlerts = new ArrayList<>();
        List<String> recentErrors = new ArrayList<>();

        int failedLoginCount = 0;
        int unauthorizedCount = 0;
        int sqlExceptionCount = 0;

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                totalLines++;
                String upperLine = line.toUpperCase();

                // 1. Log Level Aggregation
                if (upperLine.contains("ERROR") || upperLine.contains("FATAL") || upperLine.contains("SEVERE")) {
                    logLevelCounts.put("ERROR", logLevelCounts.get("ERROR") + 1);
                    if (recentErrors.size() < 10) {
                        recentErrors.add(line);
                    }
                    String truncatedError = line.length() > 100 ? line.substring(0, 100) + "..." : line;
                    topErrorMessages.put(truncatedError, topErrorMessages.getOrDefault(truncatedError, 0) + 1);
                } else if (upperLine.contains("WARN") || upperLine.contains("WARNING")) {
                    logLevelCounts.put("WARN", logLevelCounts.get("WARN") + 1);
                } else if (upperLine.contains("INFO")) {
                    logLevelCounts.put("INFO", logLevelCounts.get("INFO") + 1);
                } else if (upperLine.contains("DEBUG") || upperLine.contains("TRACE")) {
                    logLevelCounts.put("DEBUG", logLevelCounts.get("DEBUG") + 1);
                } else {
                    logLevelCounts.put("OTHER", logLevelCounts.get("OTHER") + 1);
                }

                // 2. Security & Threat Pattern Detection
                if (upperLine.contains("FAILED LOGIN") || upperLine.contains("AUTHENTICATION FAILURE") || upperLine.contains("INVALID CREDENTIALS")) {
                    failedLoginCount++;
                }
                if (upperLine.contains("401 UNAUTHORIZED") || upperLine.contains("403 FORBIDDEN") || upperLine.contains("ACCESS DENIED")) {
                    unauthorizedCount++;
                }
                if (upperLine.contains("SQLException") || upperLine.contains("SQL syntax") || upperLine.contains("hibernate.exception")) {
                    sqlExceptionCount++;
                }
            }

            // 3. Generate Security Flags
            if (failedLoginCount >= 5) {
                securityAlerts.add("BRUTE_FORCE_SUSPECTED: Detected " + failedLoginCount + " failed authentication attempts.");
            }
            if (unauthorizedCount >= 10) {
                securityAlerts.add("UNAUTHORIZED_ACCESS_SPIKE: Detected " + unauthorizedCount + " access denied events.");
            }
            if (sqlExceptionCount > 0) {
                securityAlerts.add("DATABASE_EXCEPTION: Detected " + sqlExceptionCount + " SQL errors or syntax exceptions.");
            }

            if (securityAlerts.isEmpty()) {
                securityAlerts.add("NO_CRITICAL_SECURITY_PATTERNS_DETECTED");
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to analyze log file: " + e.getMessage(), e);
        }

        return new LogAnalysisReport(
                fileName, fileSize, totalLines, logLevelCounts, topErrorMessages, securityAlerts, recentErrors, LocalDateTime.now()
        );
    }
}