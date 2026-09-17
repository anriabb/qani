package backend.demo.controllers;

import backend.demo.dto.HeaderAnalysisResponse;
import backend.demo.services.HeaderAnalyzerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v1/headers")
@Tag(name = "Email Header Security API", description = "Analyzes email authentication headers for spoofing risks")
public class HeaderScannerController {

    @Autowired
    private HeaderAnalyzerService headerService;

    @GetMapping("/scan")
    @Operation(
            summary = "Analyze Email Header Security via GET",
            description = "Evaluates SPF, DKIM, DMARC, domain alignment, and routing hops to detect email spoofing and phishing."
    )
    public ResponseEntity<HeaderAnalysisResponse> scanHeader(
            @Parameter(description = "From Header Domain or Email", example = "support@paypal.com")
            @RequestParam("from") String from,

            @Parameter(description = "Return-Path Domain or Email", example = "attacker@bad-domain.xyz")
            @RequestParam("returnPath") String returnPath,

            @Parameter(description = "SPF Status (PASS, FAIL, SOFTFAIL, NONE)", example = "FAIL")
            @RequestParam(defaultValue = "PASS") String spf,

            @Parameter(description = "DKIM Status (PASS, FAIL, NONE)", example = "FAIL")
            @RequestParam(defaultValue = "PASS") String dkim,

            @Parameter(description = "DMARC Status (PASS, FAIL, NONE)", example = "FAIL")
            @RequestParam(defaultValue = "PASS") String dmarc,

            @Parameter(description = "Total relay hops count", example = "4")
            @RequestParam(defaultValue = "1") int hops) {

        HeaderAnalysisResponse response = headerService.analyzeHeaderFields(
                from, returnPath, spf, dkim, dmarc, hops
        );

        return ResponseEntity.ok(response);
    }
}