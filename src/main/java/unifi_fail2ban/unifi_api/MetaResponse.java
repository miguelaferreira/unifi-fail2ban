package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;

@Serdeable
@Introspected
record MetaResponse(Meta meta) {
}
