package unifi_fail2ban.model;

import lombok.Builder;

@Builder
public record Alert(String srcIp, String dstIp, int dstPort) {
}
