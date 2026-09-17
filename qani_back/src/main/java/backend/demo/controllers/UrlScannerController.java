package backend.demo.controllers;

import backend.demo.dto.UrlAnalysisResponse;
import backend.demo.services.UrlAnalyzerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")

@RestController
@RequestMapping("/api/v1/urls")
@Tag(name = "URL Phishing API", description = "Endpoints for analyzing link phishing risks")
public class UrlScannerController {

    @Autowired
    private UrlAnalyzerService urlService;

    @GetMapping("/scan")
    @Operation(summary = "Scan URL for phishing risks via GET", description = "Evaluates URL parameters, domain structure, IP presence, and credential harvesting patterns.")
    public ResponseEntity<UrlAnalysisResponse> scanUrl(
            @Parameter(description = "URL to analyze", example = "http://login.paypal.com.account-update.xyz/login@auth")
            @RequestParam("url") String url) {
        try {
            UrlAnalysisResponse response = urlService.analyzeUrl(url);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}