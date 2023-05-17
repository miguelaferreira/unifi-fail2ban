package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;

import java.util.List;

@Serdeable
@Introspected
public record FirewallRulesResponse(Meta meta, List<FirewallRule> data) {
}
