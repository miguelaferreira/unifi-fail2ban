package unifi_fail2ban.model;

import io.vavr.collection.List;
import io.vavr.collection.Stream;
import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;
import unifi_fail2ban.DetectionConfiguration;

import static unifi_fail2ban.model.IpMatcher.cidrContainsIp;

@Slf4j
@Singleton
public class AlertDetectionService {

    private final List<Integer> protectedPorts;
    private final List<String> protectedCidrs;
    private final List<String> allowedSrcCidrs;
    private final String allowedCidrsString;
    private final String protectedIpsString;

    public AlertDetectionService(DetectionConfiguration configuration) {
        this.protectedPorts = List.ofAll(configuration.protectedPorts());
        this.protectedCidrs = List.ofAll(configuration.protectedCidrs());
        this.allowedSrcCidrs = List.ofAll(configuration.allowedSrcCidrs());
        allowedCidrsString = allowedSrcCidrs.mkString();
        protectedIpsString = protectedCidrs.mkString();
    }

    public AlertDetectionService(List<Integer> protectedPorts, List<String> protectedCidrs, List<String> allowedSrcCidrs) {
        this.protectedPorts = protectedPorts;
        this.protectedCidrs = protectedCidrs;
        this.allowedSrcCidrs = allowedSrcCidrs;
        allowedCidrsString = allowedSrcCidrs.mkString();
        protectedIpsString = protectedCidrs.mkString();
    }

    public Stream<Alert> scan(Stream<Alert> alerts) {
        return alerts.filter(this::match);
    }

    private boolean match(Alert event) {
        return isTargetingProtectedPort(event) && isTargetingProtectedIp(event) && !isAllowedSrcIp(event);
    }

    private boolean isAllowedSrcIp(Alert event) {
        final String ip = event.dstIp();
        final boolean result = aCidrContainsEventDstIp(allowedSrcCidrs, ip);
        log.debug("isAllowedSrcIp? {} :: ip = {}, src ips = {}", result, ip, allowedCidrsString);
        return result;
    }

    private boolean isTargetingProtectedIp(Alert event) {
        final String ip = event.dstIp();
        final boolean result = aCidrContainsEventDstIp(protectedCidrs, ip);
        log.debug("isTargetingProtectedIp? {} :: ip = {}, protected ips = {}", result, ip, protectedIpsString);
        return result;
    }

    private boolean aCidrContainsEventDstIp(List<String> cidrs, String ip) {
        return !cidrs.isEmpty() && !cidrs.filter(cidr -> cidrContainsIp(cidr, ip)).isEmpty();
    }

    private boolean isTargetingProtectedPort(Alert event) {
        return protectedPorts.contains(event.dstPort());
    }
}
