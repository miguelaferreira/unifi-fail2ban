package unifi_fail2ban;

import io.micronaut.context.annotation.ConfigurationProperties;

import java.util.List;


@ConfigurationProperties("detect")
public record DetectionConfiguration(
        String firewallGroupName,
        List<Integer> protectedPorts,
        List<String> protectedCidrs,
        List<String> allowedSrcCidrs) {
}
