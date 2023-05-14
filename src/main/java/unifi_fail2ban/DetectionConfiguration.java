package unifi_fail2ban;

import io.micronaut.context.annotation.ConfigurationProperties;

import java.util.List;


@ConfigurationProperties("detect")
public record DetectionConfiguration(
        List<Integer> protectedPorts,
        List<String> protectedCidrs,
        List<String> allowedCidrs) {

    @Override
    public String toString() {
        return "Protected Ports: " + protectedPorts +
                ", Protected Cidrs: " + protectedCidrs +
                ", Allowed Cidrs: " + allowedCidrs;
    }
}
