package backend.demo.dto;

import java.util.List;
import java.util.Map;

public class UrlInspectionResponse {

    private String rawUrl;
    private String scheme;
    private String host;
    private int port;
    private String path;
    private Map<String, String> queryParameters;
    private boolean isHttps;
    private boolean isIpBasedHost;
    private boolean containsSuspiciousPayload;
    private List<String> detectedRiskFlags;

    public UrlInspectionResponse(String rawUrl, String scheme, String host, int port,
                                 String path, Map<String, String> queryParameters,
                                 boolean isHttps, boolean isIpBasedHost,
                                 boolean containsSuspiciousPayload, List<String> detectedRiskFlags) {
        this.rawUrl = rawUrl;
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
        this.queryParameters = queryParameters;
        this.isHttps = isHttps;
        this.isIpBasedHost = isIpBasedHost;
        this.containsSuspiciousPayload = containsSuspiciousPayload;
        this.detectedRiskFlags = detectedRiskFlags;
    }

    public String getRawUrl() { return rawUrl; }
    public String getScheme() { return scheme; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getPath() { return path; }
    public Map<String, String> getQueryParameters() { return queryParameters; }
    public boolean isHttps() { return isHttps; }
    public boolean isIpBasedHost() { return isIpBasedHost; }
    public boolean isContainsSuspiciousPayload() { return containsSuspiciousPayload; }
    public List<String> getDetectedRiskFlags() { return detectedRiskFlags; }
}