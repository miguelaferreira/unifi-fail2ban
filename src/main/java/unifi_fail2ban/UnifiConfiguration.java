package unifi_fail2ban;

import io.micronaut.context.annotation.ConfigurationProperties;

@ConfigurationProperties("unifi")
public record UnifiConfiguration(
        String username,
        String password,
        String firewallGroupName
) {
    @Override
    public String toString() {
        return "Username: " + username +
                ", Password: " + (hasPassword() ? "not " : "") + "empty" +
                ", Firewall group name: " + firewallGroupName;
    }

    private boolean hasPassword() {
        return password != null && !password.isBlank();
    }
}
