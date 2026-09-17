package backend.demo.services;

import backend.demo.dto.HeaderAnalysisResponse;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class HeaderAnalyzerService {

    public HeaderAnalysisResponse analyzeHeaderFields(String fromDomain, String returnPathDomain,
                                                      String spf, String dkim, String dmarc, int hops) {
        List<String> riskFactors = new ArrayList<>();
        int threatScore = 0;

        String cleanFrom = extractDomain(fromDomain);
        String cleanReturn = extractDomain(returnPathDomain);

        // 1. Domain Alignment Check (From vs Return-Path)
        boolean aligned = cleanFrom.equalsIgnoreCase(cleanReturn);
        if (!aligned && !cleanReturn.isEmpty()) {
            threatScore += 35;
            riskFactors.add("Domain Mismatch: From domain (" + cleanFrom + ") does not match Return-Path (" + cleanReturn + ")");
        }

        // 2. SPF Validation
        String normalizedSpf = spf.trim().toUpperCase();
        if ("FAIL".equals(normalizedSpf) || "SOFTFAIL".equals(normalizedSpf)) {
            threatScore += 30;
            riskFactors.add("SPF authentication failure: " + normalizedSpf);
        } else if ("NONE".equals(normalizedSpf)) {
            threatScore += 15;
            riskFactors.add("Missing SPF validation record");
        }

        // 3. DKIM Validation
        String normalizedDkim = dkim.trim().toUpperCase();
        if ("FAIL".equals(normalizedDkim)) {
            threatScore += 30;
            riskFactors.add("DKIM cryptographic signature verification failed");
        } else if ("NONE".equals(normalizedDkim)) {
            threatScore += 15;
            riskFactors.add("Missing DKIM signature");
        }

        // 4. DMARC Validation
        String normalizedDmarc = dmarc.trim().toUpperCase();
        if ("FAIL".equals(normalizedDmarc)) {
            threatScore += 25;
            riskFactors.add("DMARC verification failed policy checks");
        }

        // 5. Excessive Hops Check
        if (hops > 8) {
            threatScore += 15;
            riskFactors.add("Suspicious mail routing: High relay hop count (" + hops + " hops)");
        }

        threatScore = Math.min(threatScore, 100);

        String threatLevel = "CLEAN";
        if (threatScore >= 60) {
            threatLevel = "MALICIOUS";
        } else if (threatScore >= 25) {
            threatLevel = "SUSPICIOUS";
        }

        return new HeaderAnalysisResponse(
                cleanFrom, cleanReturn, normalizedSpf, normalizedDkim,
                normalizedDmarc, aligned, hops, threatScore, threatLevel,
                riskFactors, LocalDateTime.now()
        );
    }

    private String extractDomain(String rawInput) {
        if (rawInput == null) return "";
        String clean = rawInput.trim().toLowerCase();
        if (clean.contains("@")) {
            clean = clean.substring(clean.indexOf("@") + 1);
        }
        if (clean.contains(">")) {
            clean = clean.replace(">", "");
        }
        return clean;
    }
}