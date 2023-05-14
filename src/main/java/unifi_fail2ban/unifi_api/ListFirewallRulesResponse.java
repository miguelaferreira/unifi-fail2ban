package unifi_fail2ban.unifi_api;

import java.util.List;

public record ListFirewallRulesResponse(Meta meta, List<FirewallRule> data) {
}
