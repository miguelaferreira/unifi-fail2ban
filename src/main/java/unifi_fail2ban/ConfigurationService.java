package unifi_fail2ban;

import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Singleton
public class ConfigurationService {

    private final UnifiConfiguration unifiConfiguration;
    private final DetectionConfiguration detectionConfiguration;

    public ConfigurationService(UnifiConfiguration unifiConfiguration, DetectionConfiguration detectionConfiguration) {
        this.unifiConfiguration = unifiConfiguration;
        this.detectionConfiguration = detectionConfiguration;
    }

    void printConfiguration() {
        log.info("Unifi Configuration:\t{}", unifiConfiguration.toString());
        log.info("Detection Configuration:\t{}", detectionConfiguration.toString());
    }
}
