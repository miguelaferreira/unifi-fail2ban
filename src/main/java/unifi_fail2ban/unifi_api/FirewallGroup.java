package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import lombok.Builder;

import java.util.List;

@Builder
@Introspected
@JsonIgnoreProperties(ignoreUnknown = true)
public record FirewallGroup(
        @JsonProperty("_id") String id,
        String name,
        @JsonProperty("group_type")
        String groupType,
        @JsonProperty("site_id") String siteId,
        @JsonProperty("group_members") List<String> members
) {

    public List<String> members() {
        return members != null ? members : List.of();
    }

    public int memberCount() {
        return members != null ? members.size() : 0;
    }
}
