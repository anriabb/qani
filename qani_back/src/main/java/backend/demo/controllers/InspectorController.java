package backend.demo.controllers;

import backend.demo.dto.IpIntelligenceResponse;
import backend.demo.dto.UrlInspectionResponse;
import backend.demo.services.IpIntelligenceService;
import backend.demo.services.UrlInspectorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v1/inspector")
@Tag(name = "IP & URL Inspector API", description = "Network geolocation, ISP lookup, and URL security inspection endpoints")
public class InspectorController {

    @Autowired
    private IpIntelligenceService ipService;

    @Autowired
    private UrlInspectorService urlService;

    @GetMapping("/ip")
    @Operation(summary = "Lookup IP Geolocation & Network Info", description = "Retrieves country, city, coordinates, ISP, ASN, and proxy/VPN flags.")
    public ResponseEntity<IpIntelligenceResponse> inspectIp(
            @Parameter(description = "Target IPv4 or IPv6 address", example = "8.8.8.8")
            @RequestParam("ip") String ip) {
        return ResponseEntity.ok(ipService.lookupIp(ip));
    }

    @GetMapping("/url")
    @Operation(summary = "Inspect URL Structure & Threats", description = "Parses host, query parameters, protocol details, and scans for SQLi, XSS, and traversal patterns.")
    public ResponseEntity<UrlInspectionResponse> inspectUrl(
            @Parameter(description = "Target URL string to analyze", example = "https://example.com/search?q=test")
            @RequestParam("url") String url) {
        return ResponseEntity.ok(urlService.inspectUrl(url));
    }
}