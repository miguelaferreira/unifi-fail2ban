package unifi_fail2ban.model;

import io.vavr.collection.List;
import io.vavr.collection.Stream;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;


class FirewallTest {

    public static final String LOCALHOST_IP = "127.0.0.1";
    public static final String PRIVATE_NETWORK_IP = "192.168.1.30";
    public static final Stream<String> LOCALHOST_AND_PRIVATE_NETWORK_IPS = Stream.of(LOCALHOST_IP, PRIVATE_NETWORK_IP);

    @ParameterizedTest
    @MethodSource("blockIps_whenIpsAreAllNew_params")
    void blockIps_whenIpsAreAllNew(Firewall initial, Stream<String> ips, Firewall updated) {
        Assertions.assertThat(initial.blockIps(ips)).isEqualTo(updated);
    }

    public static Stream<Arguments> blockIps_whenIpsAreAllNew_params() {
        return Stream.of(
                Arguments.of(new Firewall(), LOCALHOST_AND_PRIVATE_NETWORK_IPS, new Firewall(LOCALHOST_AND_PRIVATE_NETWORK_IPS)),
                Arguments.of(new Firewall(List.of(LOCALHOST_IP)), Stream.of(PRIVATE_NETWORK_IP), new Firewall(LOCALHOST_AND_PRIVATE_NETWORK_IPS)),
                Arguments.of(new Firewall(List.of(LOCALHOST_IP)), LOCALHOST_AND_PRIVATE_NETWORK_IPS, new Firewall(LOCALHOST_AND_PRIVATE_NETWORK_IPS))
        );
    }
}
