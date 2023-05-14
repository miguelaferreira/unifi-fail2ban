package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Introspected;

import java.util.List;

@Introspected
record FirewallGroupResponse(Meta meta, List<FirewallGroup> data) {
}
