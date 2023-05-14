package unifi_fail2ban;

import io.micronaut.context.annotation.ConfigurationProperties;


@ConfigurationProperties("unifi")
public record UnifiConfiguration(
        String username,
        String password
) {
}
