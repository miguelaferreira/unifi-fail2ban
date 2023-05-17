package unifi_fail2ban.unifi_api;

import org.assertj.core.api.Assertions;

import java.util.List;

class AbstractUnifiApiServiceTest {

    public static final String TEST_FIREWALL_GROUP = "tmp-firewall-group";
    public static final List<String> FIREWALL_GROUP_MEMBERS = List.of("127.0.0.1", "8.8.8.8");
    public static final String UPDATED_IP = "4.4.4.4";
    public static final List<String> UPDATED_FIREWALL_GROUP_MEMBERS = List.of(UPDATED_IP);
    final String username;
    final String password;

    public AbstractUnifiApiServiceTest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    void login(UnifiApiService service) {
        service.login(username, password);

        Assertions.assertThat(service.isLoggedIn()).as("service should be logged in").isTrue();
    }

    List<IpsEvent> listIpsAlerts(UnifiApiService service, int limit) {
        login(service);

        final List<IpsEvent> events = service.listIpsAlerts(limit);

        Assertions.assertThat(events).isNotEmpty();

        return events;
    }

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

    void deleteFirewallGroup(UnifiApiService service) {
        login(service);
        final FirewallGroup firewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);

        service.deleteFirewallGroup(firewallGroup.id());

        Assertions.assertThat(firewallGroup).isNotNull();
    }

    void updateFirewallGroup(UnifiApiService service) {
        String id = null;
        try {
            login(service);
            final FirewallGroup createdFirewallGroup = service.createFirewallGroup(TEST_FIREWALL_GROUP, FIREWALL_GROUP_MEMBERS);
            id = createdFirewallGroup.id();

            service.updateFirewallGroup(id, createdFirewallGroup.name(), createdFirewallGroup.groupType(), UPDATED_FIREWALL_GROUP_MEMBERS);
            final FirewallGroup updatedFirewallGroup = service.getFirewallGroup(id);

            Assertions.assertThat(updatedFirewallGroup).isNotNull();
            Assertions.assertThat(updatedFirewallGroup.id()).isEqualTo(id);
            Assertions.assertThat(updatedFirewallGroup.name()).isEqualTo(createdFirewallGroup.name());
            Assertions.assertThat(updatedFirewallGroup.groupType()).isEqualTo(createdFirewallGroup.groupType());
            Assertions.assertThat(updatedFirewallGroup.members()).containsExactly(UPDATED_IP);
        } finally {
            if (id != null) {
                service.deleteFirewallGroup(id);
            }
        }
    }
}
