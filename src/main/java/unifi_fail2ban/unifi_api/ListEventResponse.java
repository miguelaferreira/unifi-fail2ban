package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.serde.annotation.Serdeable;

import java.util.List;
import java.util.Objects;

@Serdeable
@Introspected
@JsonIgnoreProperties(ignoreUnknown = true)
record ListEventResponse(Meta meta, List<IpsEvent> data) implements ListResponse<IpsEvent> {

    public int getAvailable() {
        return Objects.requireNonNull(meta.count());
    }
}
