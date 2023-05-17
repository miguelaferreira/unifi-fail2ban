package unifi_fail2ban.unifi_api;

import io.micronaut.context.annotation.Value;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static unifi_fail2ban.unifi_api.UnifiApiService.DEFAULT_LIMIT;

@MicronautTest
class UnifiApiServiceTest extends AbstractUnifiApiServiceTest {

    @Value("${unifi.username}")
    String username;
    @Value("${unifi.password}")
    String password;

    @BeforeEach
    void setUp() {
        setCredentials(username, password);
    }

    @Test
    void login(UnifiApiService service) {
        super.login(service);
    }

    @Test
    void listIpsAlerts(UnifiApiService service) {
        super.listIpsAlerts(service, DEFAULT_LIMIT);
    }

    @Test
    void createFirewallGroup(UnifiApiService service) {
        super.createFirewallGroup(service);
    }

    @Test
    void listFirewallGroups(UnifiApiService service) {
        super.listFirewallGroups(service);
    }

    @Test
    void getFirewallGroup(UnifiApiService service) {
        super.getFirewallGroup(service);
    }

    @Test
    void deleteFirewallGroup(UnifiApiService service) {
        super.deleteFirewallGroup(service);
    }

    @Test
    void updateFirewallGroup(UnifiApiService service) {
        super.updateFirewallGroup(service);
    }
}
