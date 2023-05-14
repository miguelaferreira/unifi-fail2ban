package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.serde.annotation.Serdeable;

@Serdeable
@JsonIgnoreProperties(ignoreUnknown = true)
public record FirewallRule(
        @JsonProperty("_id") String id,
        String name,
        String action,
        String ruleset
) {
}
