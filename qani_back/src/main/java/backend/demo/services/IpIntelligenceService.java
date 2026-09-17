package backend.demo.services;

import backend.demo.dto.IpIntelligenceResponse;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.Map;

@Service
public class IpIntelligenceService {

    private final RestTemplate restTemplate = new RestTemplate();
    private static final String GEOLOCATION_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,query";

    public IpIntelligenceResponse lookupIp(String rawIp) {
        String cleanIp = rawIp.trim();

        if (isReservedIp(cleanIp)) {
            return new IpIntelligenceResponse(
                    cleanIp,
                    cleanIp.contains(":") ? "IPv6" : "IPv4",
                    "Internal Network", "LOCAL", "Local Subnet", "Localhost", "00000",
                    0.0, 0.0, "UTC", "Private Network / Loopback", "N/A", "N/A",
                    true, false, LocalDateTime.now()
            );
        }

        try {
            Map<String, Object> response = restTemplate.getForObject(GEOLOCATION_API_URL, Map.class, cleanIp);

            if (response != null && "success".equals(response.get("status"))) {
                return new IpIntelligenceResponse(
                        (String) response.get("query"),
                        cleanIp.contains(":") ? "IPv6" : "IPv4",
                        (String) response.get("country"),
                        (String) response.get("countryCode"),
                        (String) response.get("regionName"),
                        (String) response.get("city"),
                        (String) response.get("zip"),
                        response.get("lat") != null ? ((Number) response.get("lat")).doubleValue() : 0.0,
                        response.get("lon") != null ? ((Number) response.get("lon")).doubleValue() : 0.0,
                        (String) response.get("timezone"),
                        (String) response.get("isp"),
                        (String) response.get("org"),
                        (String) response.get("as"),
                        false,
                        Boolean.TRUE.equals(response.get("proxy")),
                        LocalDateTime.now()
                );
            }
        } catch (Exception ignored) {
            // Fallback for API failure or offline handling
        }

        return new IpIntelligenceResponse(
                cleanIp, "UNKNOWN", "Unknown", "XX", "Unknown", "Unknown", "N/A",
                0.0, 0.0, "UTC", "Lookup Failed", "N/A", "N/A",
                false, false, LocalDateTime.now()
        );
    }

    private boolean isReservedIp(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            return addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress();
        } catch (Exception e) {
            return false;
        }
    }
}