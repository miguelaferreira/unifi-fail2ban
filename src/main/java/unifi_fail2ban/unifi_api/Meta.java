package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Introspected;

@Introspected
record Meta(String rc, Integer count) {
}
