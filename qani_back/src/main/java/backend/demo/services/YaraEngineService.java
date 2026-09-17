package backend.demo.services;

import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class YaraEngineService {

    // Simple built-in YARA-like rule signatures mapping rule name -> byte pattern
    private static final Map<String, byte[]> STATIC_RULES = Map.of(
            "Win32_EICAR_Test_File", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".getBytes(),
            "Suspicious_PE_MZ_Header", new byte[] {0x4D, 0x5A}, // Executable MZ magic bytes
            "Embedded_PowerShell_Execution", "powershell -nop -w hidden -enc".getBytes()
    );

    public List<String> scan(byte[] fileBytes) {
        List<String> detectedRules = new ArrayList<>();

        for (Map.Entry<String, byte[]> entry : STATIC_RULES.entrySet()) {
            if (containsPattern(fileBytes, entry.getValue())) {
                detectedRules.add(entry.getKey());
            }
        }
        return detectedRules;
    }

    private boolean containsPattern(byte[] source, byte[] target) {
        if (target.length == 0 || source.length < target.length) return false;
        for (int i = 0; i <= source.length - target.length; i++) {
            boolean match = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }
}