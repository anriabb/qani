package backend.demo.controllers;

import backend.demo.dto.PcapAnalysisReport;
import backend.demo.services.PcapAnalyzerSystemService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v1/pcap-analyzer-system")
@Tag(name = "PCAP Packet Analyzer System API", description = "Upload PCAP/PCAPNG capture files for network protocol breakdown, IP statistics, and anomaly reports")
public class PcapAnalyzerSystemController {

    @Autowired
    private PcapAnalyzerSystemService pcapAnalyzerSystemService;

    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Upload & Analyze PCAP / PCAPNG File",
            description = "Parses raw network packet captures, calculates protocol distribution, identifies top talkers, and generates security threat diagnostics."
    )
    public ResponseEntity<PcapAnalysisReport> uploadAndAnalyzePcap(
            @Parameter(
                    description = "Select a .pcap or .pcapng file from your computer",
                    content = @Content(mediaType = MediaType.MULTIPART_FORM_DATA_VALUE, schema = @Schema(type = "string", format = "binary"))
            )
            @RequestPart("file") MultipartFile file) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        PcapAnalysisReport report = pcapAnalyzerSystemService.analyzePcapFile(file);
        return ResponseEntity.ok(report);
    }
}