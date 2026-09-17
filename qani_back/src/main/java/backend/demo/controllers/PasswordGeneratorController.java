package backend.demo.controllers;

import backend.demo.dto.PasswordResponse;
import backend.demo.services.PasswordGeneratorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/v1/passwords")
@Tag(name = "Password Generator API", description = "Generates high-entropy passwords")
public class PasswordGeneratorController {

    @Autowired
    private PasswordGeneratorService passwordService;

    @GetMapping("/generate")
    @Operation(summary = "Generate secure password", description = "Enforces minimum 16 characters using SecureRandom")
    public ResponseEntity<PasswordResponse> generatePassword(
            @Parameter(description = "Password length (Min 16)", example = "16")
            @RequestParam(defaultValue = "16") int length,

            @Parameter(description = "Include uppercase letters")
            @RequestParam(defaultValue = "true") boolean uppercase,

            @Parameter(description = "Include lowercase letters")
            @RequestParam(defaultValue = "true") boolean lowercase,

            @Parameter(description = "Include numbers")
            @RequestParam(defaultValue = "true") boolean numbers,

            @Parameter(description = "Include special characters")
            @RequestParam(defaultValue = "true") boolean specialChars) {

        PasswordResponse response = passwordService.generatePassword(
                length, uppercase, lowercase, numbers, specialChars
        );

        return ResponseEntity.ok(response);
    }
}