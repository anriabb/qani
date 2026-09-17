package backend.demo.services;

import backend.demo.dto.UrlInspectionResponse;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class UrlInspectorService {

    public UrlInspectionResponse inspectUrl(String rawUrl) {
        try {
            URI uri = new URI(rawUrl.trim());

            String scheme = uri.getScheme() != null ? uri.getScheme() : "http";
            String host = uri.getHost() != null ? uri.getHost() : "";
            int port = uri.getPort() != -1 ? uri.getPort() : (scheme.equalsIgnoreCase("https") ? 443 : 80);
            String path = uri.getPath() != null ? uri.getPath() : "/";

            Map<String, String> queryParams = extractQueryParameters(uri.getRawQuery());

            boolean isHttps = "https".equalsIgnoreCase(scheme);
            boolean isIpBased = host.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

            List<String> riskFlags = new ArrayList<>();
            if (!isHttps) riskFlags.add("UNENCRYPTED_HTTP_PROTOCOL");
            if (isIpBased) riskFlags.add("IP_HOST_HEADER");

            String decodedUrl = URLDecoder.decode(rawUrl, StandardCharsets.UTF_8).toLowerCase();

            if (decodedUrl.contains("<script>") || decodedUrl.contains("javascript:") || decodedUrl.contains("onerror=")) {
                riskFlags.add("POSSIBLE_XSS");
            }
            if (decodedUrl.contains("select ") || decodedUrl.contains("union ") || decodedUrl.contains("exec(") || decodedUrl.contains("1=1")) {
                riskFlags.add("POSSIBLE_SQLI");
            }
            if (decodedUrl.contains("../") || decodedUrl.contains("..\\") || decodedUrl.contains("/etc/passwd")) {
                riskFlags.add("PATH_TRAVERSAL_INDICATOR");
            }

            boolean containsSuspicious = !riskFlags.isEmpty();

            return new UrlInspectionResponse(
                    rawUrl, scheme, host, port, path, queryParams, isHttps, isIpBased, containsSuspicious, riskFlags
            );
        } catch (Exception e) {
            return new UrlInspectionResponse(
                    rawUrl, "INVALID", "", -1, "", Collections.emptyMap(), false, false, true, List.of("MALFORMED_URL")
            );
        }
    }

    private Map<String, String> extractQueryParameters(String rawQuery) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> params = new LinkedHashMap<>();
        String[] pairs = rawQuery.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            if (idx > 0) {
                String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
                params.put(key, value);
            }
        }
        return params;
    }
}