package backend.demo.dto;

import java.time.LocalDateTime;

public class IpIntelligenceResponse {

    private String ip;
    private String version;
    private String country;
    private String countryCode;
    private String region;
    private String city;
    private String zipCode;
    private double latitude;
    private double longitude;
    private String timezone;
    private String isp;
    private String org;
    private String asn;
    private boolean isPrivateOrLoopback;
    private boolean isProxyOrVpn;
    private LocalDateTime queriedAt;

    public IpIntelligenceResponse(String ip, String version, String country, String countryCode,
                                  String region, String city, String zipCode, double latitude,
                                  double longitude, String timezone, String isp, String org,
                                  String asn, boolean isPrivateOrLoopback, boolean isProxyOrVpn,
                                  LocalDateTime queriedAt) {
        this.ip = ip;
        this.version = version;
        this.country = country;
        this.countryCode = countryCode;
        this.region = region;
        this.city = city;
        this.zipCode = zipCode;
        this.latitude = latitude;
        this.longitude = longitude;
        this.timezone = timezone;
        this.isp = isp;
        this.org = org;
        this.asn = asn;
        this.isPrivateOrLoopback = isPrivateOrLoopback;
        this.isProxyOrVpn = isProxyOrVpn;
        this.queriedAt = queriedAt;
    }

    public String getIp() { return ip; }
    public String getVersion() { return version; }
    public String getCountry() { return country; }
    public String getCountryCode() { return countryCode; }
    public String getRegion() { return region; }
    public String getCity() { return city; }
    public String getZipCode() { return zipCode; }
    public double getLatitude() { return latitude; }
    public double getLongitude() { return longitude; }
    public String getTimezone() { return timezone; }
    public String getIsp() { return isp; }
    public String getOrg() { return org; }
    public String getAsn() { return asn; }
    public boolean isPrivateOrLoopback() { return isPrivateOrLoopback; }
    public boolean isProxyOrVpn() { return isProxyOrVpn; }
    public LocalDateTime getQueriedAt() { return queriedAt; }
}