package unifi_fail2ban.model;

import io.vavr.collection.List;
import io.vavr.collection.Stream;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;


class AlertDetectionServiceTest {

    public static final String LOCALHOST_IP = "127.0.0.1";
    public static final String PRIVATE_NETWORK_IP = "192.168.1.30";
    public static final String LOCALHOST_CIDR = "127.0.0.1/32";
    public static final String PRIVATE_NETWORK_CIDR = "192.168.1.0/24";
    public static final Alert SSH_TO_LOCALHOST = Alert.builder()
                                                      .dstPort(22)
                                                      .dstIp(LOCALHOST_IP)
                                                      .build();
    public static final Alert SSH_TO_PRIVATE_NETWORK = Alert.builder()
                                                            .dstPort(22)
                                                            .dstIp(PRIVATE_NETWORK_IP)
                                                            .build();
    public static final Alert HTTPS_TO_LOCALHOST = Alert.builder()
                                                        .dstPort(443)
                                                        .dstIp(LOCALHOST_IP)
                                                        .build();
    public static final AlertDetectionService ONLY_PORT_22 = new AlertDetectionService(List.of(22), List.empty(), List.empty());
    public static final AlertDetectionService ONLY_PORT_443 = new AlertDetectionService(List.of(443), List.empty(), List.empty());
    public static final AlertDetectionService ONLY_LOCALHOST = new AlertDetectionService(List.empty(), List.of(LOCALHOST_CIDR), List.empty());
    public static final AlertDetectionService LOCALHOST_PORT_22 = new AlertDetectionService(List.of(22), List.of(LOCALHOST_CIDR), List.empty());
    public static final AlertDetectionService LOCALHOST_PORT_443 = new AlertDetectionService(List.of(443), List.of(LOCALHOST_CIDR), List.empty());
    public static final AlertDetectionService LOCALHOST_AND_PRIVATE_NETWORK_PORT_22 = new AlertDetectionService(List.of(22), List.of(LOCALHOST_CIDR, PRIVATE_NETWORK_CIDR), List.empty());
    public static final AlertDetectionService LOCALHOST_AND_PRIVATE_NETWORK_PORT_22_ALLOWED_LOCALHOST = new AlertDetectionService(List.of(22), List.of(LOCALHOST_CIDR, PRIVATE_NETWORK_CIDR), List.of(LOCALHOST_CIDR));
    public static final Stream<Alert> EMPTY_ALERTS = Stream.empty();

    @ParameterizedTest
    @MethodSource("scan_validInputs_params")
    void scan_validInputs(AlertDetectionService alertDetectionService, Stream<Alert> newAlerts, Stream<Alert> result) {
        Assertions.assertThat(alertDetectionService.scan(newAlerts)).isEqualTo(result);
    }

    public static Stream<Arguments> scan_validInputs_params() {
        return Stream.of(
                Arguments.of(
                        Named.of("Empty detection", ONLY_PORT_22),
                        List.empty(),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Only port 22", ONLY_PORT_22),
                        List.empty(),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Only port 22", ONLY_PORT_22),
                        List.of(SSH_TO_LOCALHOST),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Only port 22", ONLY_PORT_22),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Only port 443", ONLY_PORT_443),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Localhost port 22", LOCALHOST_PORT_22),
                        List.of(SSH_TO_LOCALHOST),
                        Stream.of(SSH_TO_LOCALHOST)
                ),
                Arguments.of(
                        Named.of("Localhost port 22", LOCALHOST_PORT_22),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        Stream.of(SSH_TO_LOCALHOST)
                ),
                Arguments.of(
                        Named.of("Only port 443", ONLY_PORT_443),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Only localhost", ONLY_LOCALHOST),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        EMPTY_ALERTS
                ),
                Arguments.of(
                        Named.of("Localhost to port 443", LOCALHOST_PORT_443),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        Stream.of(HTTPS_TO_LOCALHOST)
                ),
                Arguments.of(
                        Named.of("Localhost to port 443", LOCALHOST_PORT_443),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST),
                        Stream.of(HTTPS_TO_LOCALHOST)
                ),
                Arguments.of(
                        Named.of("Localhost and private network to port 22", LOCALHOST_AND_PRIVATE_NETWORK_PORT_22),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST, SSH_TO_PRIVATE_NETWORK),
                        Stream.of(SSH_TO_LOCALHOST, SSH_TO_PRIVATE_NETWORK)
                ),
                Arguments.of(
                        Named.of("Localhost and private network to port 22 while allowing localhost", LOCALHOST_AND_PRIVATE_NETWORK_PORT_22_ALLOWED_LOCALHOST),
                        List.of(SSH_TO_LOCALHOST, HTTPS_TO_LOCALHOST, SSH_TO_PRIVATE_NETWORK),
                        Stream.of(SSH_TO_PRIVATE_NETWORK)
                )
        );
    }
}
