package unifi_fail2ban.model;

import io.vavr.collection.List;
import io.vavr.collection.Set;
import io.vavr.collection.Stream;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
public class Firewall {

    private final Set<String> blockedIps;

    public Firewall() {
        this.blockedIps = List.<String>empty().toSet();
    }

    public Firewall(List<String> blockedIps) {
        this.blockedIps = blockedIps.toSet();
    }

    public Firewall(Stream<String> blockedIps) {
        this.blockedIps = blockedIps.toSet();
    }

    public Firewall(Set<String> blockedIps) {
        this.blockedIps = blockedIps;
    }

    public Firewall blockIps(Stream<String> ips) {
        return new Firewall(blockedIps.addAll(ips));
    }
}
