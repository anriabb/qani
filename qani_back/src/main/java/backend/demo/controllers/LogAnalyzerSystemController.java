package backend.demo.controllers;

import backend.demo.dto.LogAnalysisReport;
import backend.demo.services.LogAnalyzerSystemService;
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

@RestController
@RequestMapping("/api/v1/log-analyzer-system")
@Tag(name = "Log Analyzer System API", description = "Upload log files (.log, .txt) to parse log levels, top errors, and security anomalies")
public class LogAnalyzerSystemController {

    @Autowired
    private LogAnalyzerSystemService logAnalyzerSystemService;

    @PostMapping(value = "/analyze", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Upload & Analyze Log File",
            description = "Parses plain-text or system log files, breaks down log levels (INFO, WARN, ERROR, DEBUG), lists top error occurrences, and flags brute-force or SQL exception patterns."
    )
    public ResponseEntity<LogAnalysisReport> uploadAndAnalyzeLog(
            @Parameter(
                    description = "Select a .log or .txt file to inspect",
                    content = @Content(mediaType = MediaType.MULTIPART_FORM_DATA_VALUE, schema = @Schema(type = "string", format = "binary"))
            )
            @RequestPart("file") MultipartFile file) {

        if (file.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        return ResponseEntity.ok(logAnalyzerSystemService.analyzeLogFile(file));
    }
}
