package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;

import java.util.List;

@Serdeable
@Introspected
record FirewallGroupResponse(Meta meta, List<FirewallGroup> data) {
}
