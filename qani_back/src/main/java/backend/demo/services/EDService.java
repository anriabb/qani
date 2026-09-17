package backend.demo.services;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base32;


@Service
public class EDService {

    //Base 64
    public String encode_b64(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes());
    }
    public String decode_b64(String encoded) {
        byte[] decodedBytes = Base64.getDecoder().decode(encoded);
        return new String(decodedBytes);
    }

    // Base32
    public String encode_b32(String input) {
        Base32 base32 = new Base32();
        return base32.encodeToString(input.getBytes());
    }

    public String decode_b32(String encoded) {
        Base32 base32 = new Base32();
        byte[] decodedBytes = base32.decode(encoded);
        return new String(decodedBytes);
    }

    //SHA-256
    public String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(input.getBytes());
            return bytesToHex(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("none");
        }
    }
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    //SHA-512
    public String sha512(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = digest.digest(input.getBytes());
            return byteToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            return "Error: " + e.getMessage();
        }
    }
    private String byteToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }


    //ASCII
    public String encodeAscii(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            sb.append((int) c).append(" ");
        }
        return sb.toString().trim();
    }
    public String decodeAscii(String asciiInput) {
        StringBuilder sb = new StringBuilder();
        String[] codes = asciiInput.trim().split("\\s+");
        for (String code : codes) {
            int ascii = Integer.parseInt(code);
            sb.append((char) ascii);
        }
        return sb.toString();
    }

    //Binary
    public String encodeBinary(String input) {
        StringBuilder binary = new StringBuilder();
        for (char c : input.toCharArray()) {
            binary.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0')).append(" ");
        }
        return binary.toString().trim();
    }
    public String decodeBinary(String binaryInput) {
        StringBuilder text = new StringBuilder();
        String[] binaries = binaryInput.trim().split("\\s+");
        for (String binary : binaries) {
            int charCode = Integer.parseInt(binary, 2);
            text.append((char) charCode);
        }
        return text.toString();
    }

    //Hex
    public String encodeHex(String input) {
        StringBuilder hex = new StringBuilder();
        for (char c : input.toCharArray()) {
            hex.append(String.format("%02x", (int) c));
        }
        return hex.toString();
    }
    public String decodeHex(String hexInput) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexInput.length(); i += 2) {
            String str = hexInput.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }

    //Morse Code
    private static final Map<Character, String> morseMap = Map.ofEntries(
            Map.entry('A', ".-"),    Map.entry('B', "-..."),  Map.entry('C', "-.-."),
            Map.entry('D', "-.."),   Map.entry('E', "."),     Map.entry('F', "..-."),
            Map.entry('G', "--."),   Map.entry('H', "...."),  Map.entry('I', ".."),
            Map.entry('J', ".---"),  Map.entry('K', "-.-"),   Map.entry('L', ".-.."),
            Map.entry('M', "--"),    Map.entry('N', "-."),    Map.entry('O', "---"),
            Map.entry('P', ".--."),  Map.entry('Q', "--.-"),  Map.entry('R', ".-."),
            Map.entry('S', "..."),   Map.entry('T', "-"),     Map.entry('U', "..-"),
            Map.entry('V', "...-"),  Map.entry('W', ".--"),   Map.entry('X', "-..-"),
            Map.entry('Y', "-.--"),  Map.entry('Z', "--.."),
            Map.entry('1', ".----"), Map.entry('2', "..---"), Map.entry('3', "...--"),
            Map.entry('4', "....-"), Map.entry('5', "....."), Map.entry('6', "-...."),
            Map.entry('7', "--..."), Map.entry('8', "---.."), Map.entry('9', "----."),
            Map.entry('0', "-----"), Map.entry(' ', "/")
    );
    private static final Map<String, Character> reverseMorseMap = morseMap.entrySet()
            .stream().collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
    public String encodeMorse(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toUpperCase().toCharArray()) {
            sb.append(morseMap.getOrDefault(c, "")).append(" ");
        }
        return sb.toString().trim();
    }
    public String decodeMorse(String morseCode) {
        StringBuilder sb = new StringBuilder();
        for (String code : morseCode.split(" ")) {
            sb.append(reverseMorseMap.getOrDefault(code, '?'));
        }
        return sb.toString();
    }

    //Caesar Cipher
    public String caesarEncrypt(String input, int shift) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                sb.append((char) ((c - base + shift) % 26 + base));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
    public String caesarDecrypt(String input, int shift) {
        return caesarEncrypt(input, 26 - shift);
    }

    //QR
    public String generateQRCode(String text, int width, int height) throws Exception {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        Map<EncodeHintType, Object> hints = new HashMap<>();
        hints.put(EncodeHintType.MARGIN, 1); // Less margin

        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height, hints);

        // Convert QR code to Base64 PNG
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", baos);
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }


}