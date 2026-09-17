package backend.demo.controllers;

import backend.demo.dto.JwtDecodingSystemResponse;
import backend.demo.dto.JwtEncodingSystemRequest;
import backend.demo.dto.JwtEncodingSystemResponse;
import backend.demo.services.JwtEncodingSystemService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/jwt-encoding-system")
@Tag(name = "JWT Encoding System API", description = "System for encoding/decoding and verifying JWT tokens")
public class JwtEncodingSystemController {

    @Autowired
    private JwtEncodingSystemService jwtEncodingSystemService;

    @PostMapping("/encode")
    @Operation(summary = "Encode JWT Token", description = "Generates a signed HS256 JWT using custom subject, issuer, claims, and secret key.")
    public ResponseEntity<JwtEncodingSystemResponse> encodeToken(@RequestBody JwtEncodingSystemRequest request) {
        return ResponseEntity.ok(jwtEncodingSystemService.generateToken(request));
    }

    @PostMapping("/decode")
    @Operation(summary = "Decode JWT Token", description = "Parses a JWT into Header, Payload, Signature, and verifies expiration & signature validity.")
    public ResponseEntity<JwtDecodingSystemResponse> decodeToken(
            @Parameter(description = "Raw JWT Token String") @RequestParam("token") String token,
            @Parameter(description = "Secret key to verify signature against (optional)") @RequestParam(value = "secretKey", required = false) String secretKey) {
        return ResponseEntity.ok(jwtEncodingSystemService.decodeToken(token, secretKey));
    }
}
