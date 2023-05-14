package unifi_fail2ban.unifi_api;

import io.micronaut.context.annotation.Value;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

@MicronautTest
class UnifiApiServiceTest {

    public static final String TEST_FIREWALL_GROUP = "tmp-firewall-group";
    public static final List<String> FIREWALL_GROUP_MEMBERS = List.of("127.0.0.1", "8.8.8.8");
    @Value("${unifi.username}")
    String username;
    @Value("${unifi.password}")
    String password;

    @Test
    void login(UnifiApiService service) {
        service.login(username, password);

        Assertions.assertThat(service.isLoggedIn()).as("service should be logged in").isTrue();
    }

    @Test
    void listIpsAlerts(UnifiApiService service) {
        login(service);

        final List<IpsEvent> events = service.listIpsAlerts();

        Assertions.assertThat(events).isNotEmpty();
    }

    @Test
    void createFirewallGroup(UnifiApiService service) {
        String id = null;
        try {
            login(service);

            final FirewallGroup firewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);
            id = firewallGroup.id();

            Assertions.assertThat(firewallGroup).isNotNull();
        } finally {
            if (id != null) {
                service.deleteFirewallGroup(id);
            }
        }
    }

    @Test
    void listFirewallGroups(UnifiApiService service) {
        String id = null;
        try {
            login(service);
            final FirewallGroup createdFirewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);
            id = createdFirewallGroup.id();

            final List<FirewallGroup> firewallGroups = service.listFirewallGroups();

            Assertions.assertThat(firewallGroups).isNotNull();
            Assertions.assertThat(firewallGroups).isNotEmpty();
            Assertions.assertThat(firewallGroups).contains(createdFirewallGroup);
        } finally {
            if (id != null) {
                service.deleteFirewallGroup(id);
            }
        }
    }

    @Test
    void getFirewallGroup(UnifiApiService service) {
        String id = null;
        try {
            login(service);
            final FirewallGroup createdFirewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);
            id = createdFirewallGroup.id();

            final FirewallGroup firewallGroup = service.getFirewallGroup(id);

            Assertions.assertThat(firewallGroup).isNotNull();
            Assertions.assertThat(firewallGroup).isEqualTo(createdFirewallGroup);
        } finally {
            if (id != null) {
                service.deleteFirewallGroup(id);
            }
        }
    }

    @Test
    void deleteFirewallGroup(UnifiApiService service) {
        login(service);
        final FirewallGroup firewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);

        service.deleteFirewallGroup(firewallGroup.id());

        Assertions.assertThat(firewallGroup).isNotNull();
    }

    @Test
    void updateFirewallGroup(UnifiApiService service) {
        String id = null;
        try {
            login(service);
            final FirewallGroup createdFirewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);
            id = createdFirewallGroup.id();

            service.updateFirewallGroup(id, createdFirewallGroup.name(), createdFirewallGroup.groupType(), List.of("4.4.4.4"));
            final FirewallGroup updatedFirewallGroup = service.getFirewallGroup(id);

            Assertions.assertThat(updatedFirewallGroup).isNotNull();
            Assertions.assertThat(updatedFirewallGroup.id()).isEqualTo(id);
            Assertions.assertThat(updatedFirewallGroup.name()).isEqualTo(createdFirewallGroup.name());
            Assertions.assertThat(updatedFirewallGroup.groupType()).isEqualTo(createdFirewallGroup.groupType());
            Assertions.assertThat(updatedFirewallGroup.members()).containsExactly("4.4.4.4");
        } finally {
            if (id != null) {
                service.deleteFirewallGroup(id);
            }
        }
    }
}
