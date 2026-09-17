package backend.demo.services;

import backend.demo.dto.PasswordResponse;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class PasswordGeneratorService {

    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String NUMBERS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResponse generatePassword(int length, boolean useUpper, boolean useLower, boolean useNums, boolean useSpecial) {
        // Enforce a hard minimum of 16 characters
        if (length < 16) {
            length = 16;
        }

        StringBuilder characterPool = new StringBuilder();
        List<Character> mandatoryChars = new ArrayList<>();

        if (useLower) {
            characterPool.append(LOWERCASE);
            mandatoryChars.add(LOWERCASE.charAt(secureRandom.nextInt(LOWERCASE.length())));
        }
        if (useUpper) {
            characterPool.append(UPPERCASE);
            mandatoryChars.add(UPPERCASE.charAt(secureRandom.nextInt(UPPERCASE.length())));
        }
        if (useNums) {
            characterPool.append(NUMBERS);
            mandatoryChars.add(NUMBERS.charAt(secureRandom.nextInt(NUMBERS.length())));
        }
        if (useSpecial) {
            characterPool.append(SPECIAL);
            mandatoryChars.add(SPECIAL.charAt(secureRandom.nextInt(SPECIAL.length())));
        }

        // Fallback to all character sets if none were selected
        if (characterPool.length() == 0) {
            characterPool.append(LOWERCASE).append(UPPERCASE).append(NUMBERS).append(SPECIAL);
            mandatoryChars.add(LOWERCASE.charAt(secureRandom.nextInt(LOWERCASE.length())));
            mandatoryChars.add(UPPERCASE.charAt(secureRandom.nextInt(UPPERCASE.length())));
            mandatoryChars.add(NUMBERS.charAt(secureRandom.nextInt(NUMBERS.length())));
            mandatoryChars.add(SPECIAL.charAt(secureRandom.nextInt(SPECIAL.length())));
        }

        String pool = characterPool.toString();
        List<Character> passwordChars = new ArrayList<>(mandatoryChars);

        // Fill remaining slots up to requested length
        for (int i = mandatoryChars.size(); i < length; i++) {
            passwordChars.add(pool.charAt(secureRandom.nextInt(pool.length())));
        }

        // Cryptographically shuffle to prevent predictable character positioning
        Collections.shuffle(passwordChars, secureRandom);

        StringBuilder finalPassword = new StringBuilder();
        for (char c : passwordChars) {
            finalPassword.append(c);
        }

        // Calculate Entropy: E = length * log2(poolSize)
        double entropyBits = Math.round((length * (Math.log(pool.length()) / Math.log(2))) * 100.0) / 100.0;

        String strength = "VERY STRONG";
        if (entropyBits >= 128) {
            strength = "QUANTUM RESISTANT";
        }

        return new PasswordResponse(finalPassword.toString(), length, entropyBits, strength);
    }
}