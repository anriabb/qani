package backend.demo.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class PcapAnalysisReport {

    private String fileName;
    private long fileSize;
    private int totalPackets;
    private Map<String, Integer> protocolBreakdown;
    private Map<String, Integer> topTalkers;
    private List<String> detectedThreats;
    private List<PacketSummary> samplePackets;
    private LocalDateTime analyzedAt;

    public PcapAnalysisReport(String fileName, long fileSize, int totalPackets,
                              Map<String, Integer> protocolBreakdown, Map<String, Integer> topTalkers,
                              List<String> detectedThreats, List<PacketSummary> samplePackets,
                              LocalDateTime analyzedAt) {
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.totalPackets = totalPackets;
        this.protocolBreakdown = protocolBreakdown;
        this.topTalkers = topTalkers;
        this.detectedThreats = detectedThreats;
        this.samplePackets = samplePackets;
        this.analyzedAt = analyzedAt;
    }

    public String getFileName() { return fileName; }
    public long getFileSize() { return fileSize; }
    public int getTotalPackets() { return totalPackets; }
    public Map<String, Integer> getProtocolBreakdown() { return protocolBreakdown; }
    public Map<String, Integer> getTopTalkers() { return topTalkers; }
    public List<String> getDetectedThreats() { return detectedThreats; }
    public List<PacketSummary> getSamplePackets() { return samplePackets; }
    public LocalDateTime getAnalyzedAt() { return analyzedAt; }

    public static class PacketSummary {
        private int packetNumber;
        private String sourceIp;
        private String destinationIp;
        private String protocol;
        private int length;
        private String info;

        public PacketSummary(int packetNumber, String sourceIp, String destinationIp, String protocol, int length, String info) {
            this.packetNumber = packetNumber;
            this.sourceIp = sourceIp;
            this.destinationIp = destinationIp;
            this.protocol = protocol;
            this.length = length;
            this.info = info;
        }

        public int getPacketNumber() { return packetNumber; }
        public String getSourceIp() { return sourceIp; }
        public String getDestinationIp() { return destinationIp; }
        public String getProtocol() { return protocol; }
        public int getLength() { return length; }
        public String getInfo() { return info; }
    }
}