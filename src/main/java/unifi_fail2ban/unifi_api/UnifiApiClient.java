package unifi_fail2ban.unifi_api;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.CookieValue;
import io.micronaut.http.annotation.Delete;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Put;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.client.annotation.Client;

import java.util.Map;

@Client("https://${unifi.host}")
interface UnifiApiClient {

    String COOKIE_NAME_AUTH_TOKEN = "TOKEN";
    String X_CSRF_TOKEN_HEADER = "x-csrf-token";

    @Post("/api/auth/login")
    HttpResponse<Map<String, Object>> login(String username, String password);

    @Get("/proxy/network/api/s/${unifi.site:default}/stat/event")
    ListEventsResponse listEvents(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @QueryValue("_start") int startIndex,
            @QueryValue("_limit") int limit
    );

    @Get("/proxy/network/api/s/${unifi.site:default}/stat/ips/event")
    ListEventsResponse listIpsEvents(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @QueryValue("_start") int startIndex,
            @QueryValue("_limit") int limit
    );

    @Post("/proxy/network/api/s/${unifi.site:default}/rest/firewallgroup")
    FirewallGroupResponse createFirewallGroup(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @Header(X_CSRF_TOKEN_HEADER) String csrfToken,
            @Body FirewallGroupBody body
    );

    @Delete("/proxy/network/api/s/${unifi.site:default}/rest/firewallgroup/{groupId}")
    MetaResponse deleteFirewallGroup(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @Header(X_CSRF_TOKEN_HEADER) String csrfToken,
            String groupId
    );

    @Get("/proxy/network/api/s/${unifi.site:default}/rest/firewallgroup/{groupId}")
    FirewallGroupResponse getFirewallGroup(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @Header(X_CSRF_TOKEN_HEADER) String csrfToken,
            @Nullable String groupId
    );

    @Put("/proxy/network/api/s/${unifi.site:default}/rest/firewallgroup/{groupId}")
    MetaResponse updateFirewallGroup(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @Header(X_CSRF_TOKEN_HEADER) String csrfToken,
            String groupId,
            @Body FirewallGroupBody body
    );

    @Get("/proxy/network/api/s/${unifi.site:default}/rest/firewallrule/")
    ListFirewallRulesResponse getFirewallRule(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @Header(X_CSRF_TOKEN_HEADER) String csrfToken
    );

    @Delete("/proxy/network/api/s/${unifi.site:default}/rest/firewallrule/{ruleId}")
    Map<String, Object> deleteFirewallRule(
            @CookieValue(COOKIE_NAME_AUTH_TOKEN) String authToken,
            @Header(X_CSRF_TOKEN_HEADER) String csrfToken,
            String ruleId
    );
}
