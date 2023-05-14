package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;

import java.util.List;

@Serdeable
@Introspected
record FirewallGroupBody(
        @JsonProperty("_id") String id,
        String name,
        @JsonProperty("group_type") String groupType,
        @JsonProperty("group_members") List<String> groupMembers
) {
}
