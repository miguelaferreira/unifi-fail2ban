package unifi_fail2ban;

import io.micronaut.configuration.picocli.PicocliRunner;
import io.micronaut.context.annotation.Value;
import io.vavr.collection.Stream;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine.Command;
import unifi_fail2ban.model.Alert;
import unifi_fail2ban.model.AlertDetectionService;
import unifi_fail2ban.model.Firewall;
import unifi_fail2ban.unifi_api.FirewallGroup;
import unifi_fail2ban.unifi_api.IpsEvent;
import unifi_fail2ban.unifi_api.UnifiApiService;

import java.util.Objects;

@Slf4j
@Command(name = "unifi-fail2ban", description = "...",
        mixinStandardHelpOptions = true)
public class UnifiFail2banCommand implements Runnable {

    @Inject
    UnifiApiService apiService;

    @Inject
    AlertDetectionService detectionService;

    @Inject
    DetectionConfiguration detectionConfiguration;

    @Inject
    UnifiConfiguration unifiConfiguration;

    @Value("${unifi.host}")
    String unifiHost;

    public static void main(String[] args) {
        PicocliRunner.run(UnifiFail2banCommand.class, args);
    }

    public void run() {

        final String username = unifiConfiguration.username();
        log.info("Authenticating user {} to Unifi at {}", username, unifiHost);
        apiService.login(username, unifiConfiguration.password());

        final FirewallGroup initialFirewallGroup = getOrCreateFirewallGroup();
        log.info("Firewall group has {} members", initialFirewallGroup.memberCount());
        final Stream<IpsEvent> ipsEvents = getIpsEvents();
        log.info("Retrieved {} IPS events from Unifi", ipsEvents.size());

        final Firewall initialFirewall = ModelAntiCorruptionLayer.convert(initialFirewallGroup);
        final Stream<Alert> alerts = ModelAntiCorruptionLayer.convert(ipsEvents);
        final Stream<String> matchedSrcIps = detectionService.scan(alerts).map(Alert::srcIp);
        log.info("Matched {} src IPs from IPS events", matchedSrcIps.size());
        final Firewall updatedFirewall = initialFirewall.blockIps(matchedSrcIps);

        final FirewallGroup updatedFirewallGroup = ModelAntiCorruptionLayer.convert(initialFirewallGroup, updatedFirewall);
        log.info("Firewall group will have {} members", updatedFirewallGroup.members().size());
        apiService.updateFirewallGroup(updatedFirewallGroup);
        log.info("Done!");
    }

    private Stream<IpsEvent> getIpsEvents() {
        return Stream.ofAll(apiService.listIpsAlerts());
    }

    private FirewallGroup getOrCreateFirewallGroup() {
        final String firewallGroupName = detectionConfiguration.firewallGroupName();
        log.debug("Looking for firewall group named {}", firewallGroupName);
        final Stream<FirewallGroup> firewallGroups = Stream.ofAll(apiService.listFirewallGroups())
                                                           .filter(firewallGroup -> Objects.equals(firewallGroup.name(), firewallGroupName));
        log.debug("Found {} firewall groups", firewallGroups.size());
        return firewallGroups.headOption()
                             .getOrElse(() -> {
                                 log.info("Creating firewall group named {}", firewallGroupName);
                                 return apiService.createFirewallGroup(firewallGroupName);
                             });
    }
}
