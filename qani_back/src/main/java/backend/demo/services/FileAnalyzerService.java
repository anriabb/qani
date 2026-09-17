package backend.demo.services;
import backend.demo.entities.AnalysisReport;
import backend.demo.repositories.AnalysisReportRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class FileAnalyzerService {

    @Autowired
    private YaraEngineService yaraEngine;

    @Autowired
    private AnalysisReportRepository reportRepository;

    private static final Pattern IOC_PATTERN = Pattern.compile(
            "(http[s]?://[a-zA-Z0-9.-]+|cmd\\.exe|powershell|regadd|eval\\()", Pattern.CASE_INSENSITIVE
    );

    public AnalysisReport analyze(MultipartFile file) throws IOException, NoSuchAlgorithmException {
        byte[] bytes = file.getBytes();

        // 1. Calculate Cryptographic Fingerprints
        String sha256 = calculateHash(bytes, "SHA-256");

        // Return cached report if file hash already exists in DB
        Optional<AnalysisReport> existingReport = reportRepository.findById(sha256);
        if (existingReport.isPresent()) {
            return existingReport.get();
        }

        String md5 = calculateHash(bytes, "MD5");
        String sha1 = calculateHash(bytes, "SHA-1");

        // 2. Magic Bytes Inspection
        boolean isExecutableHeader = bytes.length >= 2 && bytes[0] == (byte) 0x4D && bytes[1] == (byte) 0x5A;
        boolean isDeclaredPdf = file.getOriginalFilename() != null && file.getOriginalFilename().toLowerCase().endsWith(".pdf");
        boolean headerMismatched = isExecutableHeader && isDeclaredPdf; // e.g. Executable disguised as PDF

        // 3. Calculate Shannon Entropy
        double entropy = calculateEntropy(bytes);

        // 4. Pattern Engine & Suspicious Strings Scanner
        List<String> yaraMatches = yaraEngine.scan(bytes);
        List<String> extractedIOCs = extractSuspiciousStrings(bytes);

        // 5. Threat Score Calculation Engine
        int threatScore = 0;
        if (headerMismatched) threatScore += 45; // Extension Spoofing
        if (entropy > 7.2) threatScore += 30;    // Packed / Encrypted
        if (!yaraMatches.isEmpty()) threatScore += (yaraMatches.size() * 25);
        if (!extractedIOCs.isEmpty()) threatScore += (extractedIOCs.size() * 10);
        threatScore = Math.min(threatScore, 100);

        String threatLevel = "CLEAN";
        if (threatScore >= 70) threatLevel = "MALICIOUS";
        else if (threatScore >= 30) threatLevel = "SUSPICIOUS";

        // 6. Build and Persist Report
        AnalysisReport report = new AnalysisReport();
        report.setSha256(sha256);
        report.setMd5(md5);
        report.setSha1(sha1);
        report.setFileName(file.getOriginalFilename());
        report.setMimeType(file.getContentType());
        report.setFileSize(file.getSize());
        report.setEntropy(entropy);
        report.setHeaderMismatched(headerMismatched);
        report.setMatchedYaraRules(yaraMatches);
        report.setExtractedSuspiciousStrings(extractedIOCs);
        report.setThreatScore(threatScore);
        report.setThreatLevel(threatLevel);
        report.setScannedAt(LocalDateTime.now());

        return reportRepository.save(report);
    }

    private String calculateHash(byte[] bytes, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = digest.digest(bytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private double calculateEntropy(byte[] data) {
        if (data.length == 0) return 0.0;
        int[] counts = new int[256];
        for (byte b : data) counts[b & 0xFF]++;
        double entropy = 0.0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / data.length;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return Math.round(entropy * 100.0) / 100.0;
    }

    private List<String> extractSuspiciousStrings(byte[] bytes) {
        String content = new String(bytes);
        Matcher matcher = IOC_PATTERN.matcher(content);
        Set<String> matches = new HashSet<>();
        while (matcher.find()) {
            matches.add(matcher.group());
        }
        return new ArrayList<>(matches);
    }
}