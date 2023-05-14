package unifi_fail2ban.model;

import inet.ipaddr.IPAddressString;

public class IpMatcher {

    private IpMatcher() {
    }

    public static boolean cidrContainsIp(String cidr, String ip) {
        IPAddressString cidrAddress = new IPAddressString(cidr);
        IPAddressString ipAddress = new IPAddressString(ip);
        return cidrAddress.contains(ipAddress);
    }
}
