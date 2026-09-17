package backend.demo.dto;

public class PasswordResponse {

    private String password;
    private int length;
    private double entropyBits;
    private String strengthRating;

    public PasswordResponse(String password, int length, double entropyBits, String strengthRating) {
        this.password = password;
        this.length = length;
        this.entropyBits = entropyBits;
        this.strengthRating = strengthRating;
    }

    public String getPassword() { return password; }
    public int getLength() { return length; }
    public double getEntropyBits() { return entropyBits; }
    public String getStrengthRating() { return strengthRating; }
}