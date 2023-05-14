package unifi_fail2ban;

import io.vavr.collection.List;
import io.vavr.collection.Stream;
import unifi_fail2ban.model.Alert;
import unifi_fail2ban.model.Firewall;
import unifi_fail2ban.unifi_api.FirewallGroup;
import unifi_fail2ban.unifi_api.IpsEvent;

public class ModelAntiCorruptionLayer {
    private ModelAntiCorruptionLayer() {
    }

    public static Alert convert(IpsEvent event) {
        return Alert.builder()
                    .dstPort(Integer.parseInt(event.dstPort()))
                    .dstIp(event.dstIp())
                    .srcIp(event.srcIp())
                    .build();
    }

    public static Firewall convert(FirewallGroup firewallGroup) {
        return new Firewall(List.ofAll(firewallGroup.members()));
    }

    public static Stream<Alert> convert(Stream<IpsEvent> events) {
        return events.map(ModelAntiCorruptionLayer::convert);
    }

    public static FirewallGroup convert(FirewallGroup firewallGroup, Firewall firewall) {
        return FirewallGroup.builder()
                            .id(firewallGroup.id())
                            .groupType(firewallGroup.groupType())
                            .name(firewallGroup.name())
                            .siteId(firewallGroup.siteId())
                            .members(firewall.getBlockedIps().toJavaList())
                            .build();
    }
}
