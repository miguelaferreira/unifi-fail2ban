package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micronaut.core.annotation.Introspected;
import lombok.Builder;

@Builder
@Introspected
@JsonIgnoreProperties(ignoreUnknown = true)
public record IpsEvent(
        @JsonProperty("_id") String id,
        String key,
        @JsonProperty("in_iface") String inInterface,
        @JsonProperty("src_ip") String srcIp,
        @JsonProperty("src_port") String srcPort,
        @JsonProperty("srcipCountry") String srcIpCountry,
        @JsonProperty("dest_ip") String dstIp,
        @JsonProperty("dest_port") String dstPort,
        @JsonProperty("dstipCountry") String dstIpCountry,
        @JsonProperty("proto") String protocol,
        @JsonProperty("inner_alert_signature") String alertSignature,
        @JsonProperty("inner_alert_category") String alertCategory
) {
}
