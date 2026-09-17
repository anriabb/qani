package backend.demo.controllers;

import backend.demo.entities.AnalysisReport;
import backend.demo.services.FileAnalyzerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/files")
@Tag(name = "File Scanner API", description = "Endpoints for file threat analysis")
public class FileScannerController {

    @Autowired
    private FileAnalyzerService analyzerService;

    @PostMapping(value = "/scan", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload and analyze a file", description = "Uploads a file to perform hash, entropy, and pattern checks.")
    public ResponseEntity<AnalysisReport> uploadAndScan(
            @Parameter(description = "Select file to upload", required = true)
            @RequestParam("file") MultipartFile file) {
        try {
            AnalysisReport report = analyzerService.analyze(file);
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}
