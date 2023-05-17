package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.cookie.Cookie;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static unifi_fail2ban.unifi_api.UnifiApiClient.COOKIE_NAME_AUTH_TOKEN;
import static unifi_fail2ban.unifi_api.UnifiApiService.ADDRESS_GROUP;

@ExtendWith(MockitoExtension.class)
class UnifiApiServiceTest extends AbstractUnifiApiServiceTest {

    public static final String USERNAME = "mock-username";
    public static final String PASSWORD = "mock-password";
    public static final String AUTH_TOKEN = "mock-auth-token";
    public static final String CSRF_TOKEN = "";
    public static final String OK = "ok";
    public static final MetaResponse META_RESPONSE = new MetaResponse(new Meta(OK));
    public static final String GROUP_ID = "group-id";
    public static final String SITE_ID = "site-id";

    @Mock
    UnifiApiClient client;
    UnifiApiService service;

    public UnifiApiServiceTest() {
        super(USERNAME, PASSWORD);
    }

    @BeforeEach
    void setUp() {
        service = new UnifiApiService(new ObjectMapper(), client);

        final HttpResponse loginResponse = mock(HttpResponse.class);
        final Cookie authCookie = mock(Cookie.class);
        when(authCookie.getValue()).thenReturn(AUTH_TOKEN);
        when(loginResponse.getCookie(COOKIE_NAME_AUTH_TOKEN)).thenReturn(Optional.of(authCookie));
        when(client.login(USERNAME, PASSWORD)).thenReturn(loginResponse);
    }

    @Test
    void login() {
        super.login(service);
    }

    @Test
    void listIpsAlerts() {
        // setup mocks
        int limit = 2;
        int eventsTotal = limit + limit + 1;
        final Meta listEventsResponseMeta = new Meta(OK, eventsTotal);
        final List<IpsEvent> firstBatch = List.of(
                IpsEvent.builder().id("1").build(),
                IpsEvent.builder().id("2").build()
        );
        final List<IpsEvent> secondBatch = List.of(
                IpsEvent.builder().id("3").build(),
                IpsEvent.builder().id("4").build()
        );
        final List<IpsEvent> thirdBatch = List.of(
                IpsEvent.builder().id("5").build()
        );
        when(client.listIpsEvents(AUTH_TOKEN, 0, limit))
                .thenReturn(buildListEventsResponse(listEventsResponseMeta, firstBatch));
        when(client.listIpsEvents(AUTH_TOKEN, 2, limit))
                .thenReturn(buildListEventsResponse(listEventsResponseMeta, secondBatch));
        when(client.listIpsEvents(AUTH_TOKEN, 4, limit))
                .thenReturn(buildListEventsResponse(listEventsResponseMeta, thirdBatch));
        // call abstract test method
        final List<IpsEvent> ipsEvents = super.listIpsAlerts(service, limit);
        // extra assertions
        Assertions.assertThat(ipsEvents).hasSize(eventsTotal);
        verify(client, times(3)).listIpsEvents(eq(AUTH_TOKEN), anyInt(), eq(limit));
    }

    @Test
    void createFirewallGroup() {
        // setup mocks
        mockCreateFirewallGroup();
        mockDeleteFirewallGroup();
        // call abstract test method
        super.createFirewallGroup(service);
    }

    @Test
    void listFirewallGroups() {
        // setup mocks
        mockCreateFirewallGroup();
        mockDeleteFirewallGroup();
        when(client.getFirewallGroup(AUTH_TOKEN, CSRF_TOKEN, null))
                .thenReturn(buildFirewallGroupResponse(buildFirewallGroup(FIREWALL_GROUP_MEMBERS)));
        // call abstract test method
        super.listFirewallGroups(service);
    }

    @Test
    void getFirewallGroup() {
        // setup mocks
        mockCreateFirewallGroup();
        mockDeleteFirewallGroup();
        mockGetFirewallGroup();
        // call abstract test method
        super.getFirewallGroup(service);
    }

    @Test
    void deleteFirewallGroup() {
        // setup mocks
        mockCreateFirewallGroup();
        mockDeleteFirewallGroup();
        // call abstract test method
        super.deleteFirewallGroup(service);
    }

    @Test
    void updateFirewallGroup() {
        // setup mocks
        mockCreateFirewallGroup();
        mockDeleteFirewallGroup();
        mockGetFirewallGroup(UPDATED_FIREWALL_GROUP_MEMBERS);
        when(client.updateFirewallGroup(
                AUTH_TOKEN,
                CSRF_TOKEN,
                GROUP_ID,
                new FirewallGroupBody(GROUP_ID, TEST_FIREWALL_GROUP, ADDRESS_GROUP, UPDATED_FIREWALL_GROUP_MEMBERS))
        ).thenReturn(META_RESPONSE);
        // call abstract test method
        super.updateFirewallGroup(service);
    }

    private static ListEventResponse buildListEventsResponse(Meta listEventsResponseMeta, List<IpsEvent> data) {
        return new ListEventResponse(listEventsResponseMeta, data);
    }

    private void mockGetFirewallGroup(List<String> firewallGroupMembers) {
        when(client.getFirewallGroup(AUTH_TOKEN, CSRF_TOKEN, GROUP_ID))
                .thenReturn(buildFirewallGroupResponse(buildFirewallGroup(firewallGroupMembers)));
    }

    private void mockGetFirewallGroup() {
        mockGetFirewallGroup(FIREWALL_GROUP_MEMBERS);
    }

    private void mockDeleteFirewallGroup() {
        when(client.deleteFirewallGroup(
                AUTH_TOKEN,
                CSRF_TOKEN,
                GROUP_ID)
        ).thenReturn(META_RESPONSE);
    }

    private void mockCreateFirewallGroup() {
        when(client.createFirewallGroup(
                AUTH_TOKEN,
                CSRF_TOKEN,
                new FirewallGroupBody(null, TEST_FIREWALL_GROUP, ADDRESS_GROUP, FIREWALL_GROUP_MEMBERS))
        ).thenReturn(buildFirewallGroupResponse(buildFirewallGroup(FIREWALL_GROUP_MEMBERS)));
    }

    private static FirewallGroupResponse buildFirewallGroupResponse(FirewallGroup firewallGroup) {
        return new FirewallGroupResponse(new Meta(OK), List.of(firewallGroup));
    }

    private static FirewallGroup buildFirewallGroup(List<String> firewallGroupMembers) {
        return new FirewallGroup(GROUP_ID, TEST_FIREWALL_GROUP, ADDRESS_GROUP, SITE_ID, firewallGroupMembers);
    }
}
