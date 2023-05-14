package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;

import java.util.List;

@Serdeable
@Introspected
@JsonIgnoreProperties(ignoreUnknown = true)
record ListEventsResponse(Meta meta, List<IpsEvent> data) {

    int getAvailable() {
        return meta.count();
    }
}
