package backend.demo.dto;

import java.util.Map;

public class UrlAnalysisResult {

    private String rawUrl;
    private String scheme;
    private String host;
    private int port;
    private String path;
    private Map<String, String> queryParameters;
    private boolean isHttps;
    private boolean containsSuspiciousKeywords;
    private boolean isIpBasedHost;

    public UrlAnalysisResult(String rawUrl, String scheme, String host, int port,
                             String path, Map<String, String> queryParameters,
                             boolean isHttps, boolean containsSuspiciousKeywords,
                             boolean isIpBasedHost) {
        this.rawUrl = rawUrl;
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.path = path;
        this.queryParameters = queryParameters;
        this.isHttps = isHttps;
        this.containsSuspiciousKeywords = containsSuspiciousKeywords;
        this.isIpBasedHost = isIpBasedHost;
    }

    public String getRawUrl() { return rawUrl; }
    public String getScheme() { return scheme; }
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getPath() { return path; }
    public Map<String, String> getQueryParameters() { return queryParameters; }
    public boolean isHttps() { return isHttps; }
    public boolean isContainsSuspiciousKeywords() { return containsSuspiciousKeywords; }
    public boolean isIpBasedHost() { return isIpBasedHost; }
}