package unifi_fail2ban.unifi_api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.cookie.Cookie;
import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static unifi_fail2ban.unifi_api.UnifiApiClient.COOKIE_NAME_AUTH_TOKEN;

@Slf4j
@Singleton
public class UnifiApiService {

    public static final TypeReference<HashMap<String, String>> TYPE_REF = new TypeReference<>() {
    };
    public static final String CSRF_TOKEN_KEY = "csrfToken";
    public static final String ADDRESS_GROUP = "address-group";
    public static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();

    private final ObjectMapper mapper;
    private final UnifiApiClient client;
    private Cookie authCookie;

    public UnifiApiService(ObjectMapper mapper, UnifiApiClient client) {
        this.mapper = mapper;
        this.client = client;
    }

    public void login(String username, String password) {
        final HttpResponse<Map<String, Object>> loginResponse = client.login(username, password);

        authCookie = loginResponse.getCookie(COOKIE_NAME_AUTH_TOKEN)
                                  .orElseThrow(() -> new RuntimeException("Could not get " + COOKIE_NAME_AUTH_TOKEN + " cookie"));
    }

    public List<IpsEvent> listIpsAlerts() {
        final String authToken = getAuthToken();
        final ListEventsResponse firstResponse = client.listIpsEvents(authToken, 0, 100);
        final List<IpsEvent> firstBatch = firstResponse.data();
        final List<IpsEvent> events = new ArrayList<>(firstBatch);
        final int available = firstResponse.getAvailable();
        log.debug("There are {} events avaialble", available);
        log.debug("First request returned {} events", firstBatch.size());
        while (events.size() < available) {
            final ListEventsResponse response = client.listIpsEvents(authToken, events.size(), 100);
            final List<IpsEvent> batch = response.data();
            log.debug("Request returned {} events", batch.size());
            events.addAll(batch);
        }
        return events;
    }

    public FirewallGroup createFirewallGroup(String name, List<String> members) {
        return client.createFirewallGroup(getAuthToken(), csrfToken(), new FirewallGroupBody(null, name, ADDRESS_GROUP, members))
                     .data().get(0);
    }

    public FirewallGroup createFirewallGroup(String name) {
        return createFirewallGroup(name, List.of());
    }

    public void updateFirewallGroup(FirewallGroup group) {
        updateFirewallGroup(group.id(), group.name(), group.groupType(), group.members());
    }

    public void updateFirewallGroup(String groupId, String name, String groupType, List<String> members) {
        client.updateFirewallGroup(getAuthToken(), csrfToken(), groupId, new FirewallGroupBody(groupId, name, groupType, members));
    }

    public List<FirewallGroup> listFirewallGroups() {
        return client.getFirewallGroup(getAuthToken(), csrfToken(), null).data();
    }

    public FirewallGroup getFirewallGroup(String groupId) {
        return client.getFirewallGroup(getAuthToken(), csrfToken(), groupId).data().get(0);
    }

    public void deleteFirewallGroup(String groupId) {
        client.deleteFirewallGroup(getAuthToken(), csrfToken(), groupId);
    }

    String getAuthToken() {
        return authCookie.getValue();
    }


    boolean isLoggedIn() {
        return authCookie != null && !authCookie.getValue().isBlank();
    }

    String csrfToken() {
        final String[] tokenParts = getAuthToken().split("\\.");
        if (tokenParts.length > 1) {
            try {
                final byte[] json = BASE64_DECODER.decode(tokenParts[1]);
                final Map<String, String> map = mapper.readValue(json, TYPE_REF);
                return map.get(CSRF_TOKEN_KEY);
            } catch (IOException e) {
                log.warn("Could not parse token part into JSON", e);
            }
        }
        log.warn("Could not parse token part into JSON");
        return "";
    }

    List<FirewallRule> getFirewallRules() {
        return client.getFirewallRule(getAuthToken(), csrfToken()).data();
    }

    Map<String, Object> deleteFirewallRule(String ruleId) {
        return client.deleteFirewallRule(getAuthToken(), csrfToken(), ruleId);
    }
}
