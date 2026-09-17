package backend.demo.services;

import backend.demo.dto.UrlAnalysisResponse;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class UrlAnalyzerService {

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^https?://(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?::[0-9]+)?.*$", Pattern.CASE_INSENSITIVE
    );

    private static final List<String> SENSITIVE_KEYWORDS = List.of(
            "login", "verify", "banking", "secure", "account", "update", "signin", "paypal", "appleid"
    );

    public UrlAnalysisResponse analyzeUrl(String rawUrl) throws Exception {
        String normalizedUrl = rawUrl.trim().toLowerCase();
        if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
            normalizedUrl = "http://" + normalizedUrl;
        }

        String urlHash = calculateSha256(normalizedUrl);
        URI uri = new URI(normalizedUrl);
        String domain = uri.getHost() != null ? uri.getHost() : "";

        boolean usesHttps = "https".equalsIgnoreCase(uri.getScheme());
        boolean isIp = IP_PATTERN.matcher(normalizedUrl).matches();

        String[] domainParts = domain.split("\\.");
        int subdomainCount = Math.max(0, domainParts.length - 2);

        List<String> riskFactors = new ArrayList<>();
        int threatScore = 0;

        // 1. Check IP use
        if (isIp) {
            threatScore += 35;
            riskFactors.add("URL uses raw IP address instead of domain name");
        }

        // 2. Protocol check
        if (!usesHttps) {
            threatScore += 15;
            riskFactors.add("Insecure protocol (HTTP)");
        }

        // 3. Subdomain count
        if (subdomainCount >= 3) {
            threatScore += 25;
            riskFactors.add("Excessive subdomains detected (" + subdomainCount + ")");
        }

        // 4. URL length
        if (normalizedUrl.length() > 75) {
            threatScore += 15;
            riskFactors.add("Abnormally long URL length (" + normalizedUrl.length() + " chars)");
        }

        // 5. Host spoofing check ('@' character)
        if (normalizedUrl.contains("@")) {
            threatScore += 30;
            riskFactors.add("Contains '@' symbol (used for credentials/host spoofing)");
        }

        // 6. Sensitive keyword targeting
        for (String keyword : SENSITIVE_KEYWORDS) {
            if (normalizedUrl.contains(keyword) && !domain.contains(keyword)) {
                threatScore += 20;
                riskFactors.add("Targeting sensitive keyword outside main domain: " + keyword);
                break;
            }
        }

        threatScore = Math.min(threatScore, 100);

        String threatLevel = "CLEAN";
        if (threatScore >= 65) {
            threatLevel = "MALICIOUS";
        } else if (threatScore >= 30) {
            threatLevel = "SUSPICIOUS";
        }

        return new UrlAnalysisResponse(
                urlHash, rawUrl, domain, usesHttps, isIp,
                subdomainCount, threatScore, threatLevel, riskFactors, LocalDateTime.now()
        );
    }

    private String calculateSha256(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}