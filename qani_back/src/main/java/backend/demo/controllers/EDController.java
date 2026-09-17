package backend.demo.controllers;

import backend.demo.services.EDService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
@CrossOrigin(origins = "*")
@RestController
@RequestMapping("api/v1/cipher")
@Tag(name = "Encryption / Decryption API", description = "Encryption/Decryption")
public class EDController {

    @Autowired
    private EDService edService;

    //Base64
    @GetMapping(value = "/encode_b64", produces = "application/json")
    public String encode_base64(@RequestParam String input) {
        return edService.encode_b64(input);
    }
    @GetMapping(value = "/decode_b64", produces = "application/json")
    public String decode_base64(@RequestParam String input) {
        return edService.decode_b64(input);
    }

    //Base32
    @GetMapping(value = "/encode_b32", produces = {"application/json"})
    public String encode_base32(@RequestParam String input) {
        return edService.encode_b32(input);
    }
    @GetMapping(value = "/decode_b32", produces = {"application/json"})
    public String decode_base32(@RequestParam String input) {
        return edService.decode_b32(input);
    }

    //SHA256
    @GetMapping(value = "/sha256", produces = {"application/json"})
    public String hashSha256(@RequestParam String input) {
        return edService.sha256(input);
    }

    //SHA512
    @GetMapping(value = "/sha512", produces = {"application/json"})
    public String hashSha512(@RequestParam String input) {
        return edService.sha512(input);
    }

    //ASCII
    @GetMapping(value = "/encode_ascii", produces = {"application/json"})
    public String encode_ascii(@RequestParam String input) {
        return edService.encodeAscii(input);
    }
    @GetMapping(value = "/decode_ascii", produces = {"application/json"})
    public String decode_ascii(@RequestParam String input) {
        return edService.decodeAscii(input);
    }

    //Binary
    @GetMapping(value = "/encode_binary", produces = {"application/json"})
    public String encode_binary(@RequestParam String input) {
        return edService.encodeBinary(input);
    }
    @GetMapping(value = "/decode_binary", produces = {"application/json"})
    public String decode_binary(@RequestParam String input) {
        return edService.decodeBinary(input);
    }

    //Hex
    @GetMapping(value = "/encode_hex", produces = {"application/json"})
    public String encode_hex(@RequestParam String input) {
        return edService.encodeHex(input);
    }
    @GetMapping(value = "/decode_hex", produces = {"application/json"})
    public String decode_hex(@RequestParam String input) {
        return edService.decodeHex(input);
    }

    //Morse Code
    @GetMapping(value = "/encode_morse", produces = {"application/json"})
    public String encode_morse(@RequestParam String input) {
        return edService.encodeMorse(input);
    }
    @GetMapping(value = "/decode_morse", produces = {"application/json"})
    public String decode_morse(@RequestParam String input) {
        return edService.decodeMorse(input);
    }

    //Caesar Cipher
    @GetMapping(value = "/e", produces = {"application/json"})
    public String caesar_en(@RequestParam String input, @RequestParam Integer shift) {
        return edService.caesarEncrypt(input, shift);
    }
    @GetMapping(value = "/caesar_de", produces = {"application/json"})
    public String caesar_de(@RequestParam String input, @RequestParam Integer shift) {
        return edService.caesarDecrypt(input, shift);
    }

    //QR Generator
    @GetMapping(value = "/qr", produces = {"application/json"})
    public String getQRCode(@RequestParam String text) throws Exception {
        String base64Image = edService.generateQRCode(text, 250, 250);
        return "<img src='data:image/png;base64," + base64Image + "' />";
    }





}
