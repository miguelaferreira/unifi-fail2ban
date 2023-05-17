package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;

@Serdeable
@Introspected
record Meta(String rc, @Nullable Integer count, @Nullable String name, @Nullable String msg) {
    public Meta(String ok) {
        this(ok, null, null, null);
    }

    public Meta(String ok, int count) {
        this(ok, count, null, null);
    }
}
