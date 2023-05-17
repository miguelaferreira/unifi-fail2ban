package unifi_fail2ban.model;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static unifi_fail2ban.model.IpMatcher.cidrContainsIp;


class IpMatcherTest {

    @ParameterizedTest
    @MethodSource("cidrContainsIp_validInputs_params")
    void cidrContainsIp_validInputs(String cidr, String ip, boolean isContained) {
        Assertions.assertThat(cidrContainsIp(cidr, ip))
                  .as("ip should " + (isContained ? "" : "not ") + "be contained in CIDR")
                  .isEqualTo(isContained);
    }

    public static Stream<Arguments> cidrContainsIp_validInputs_params() {
        return Stream.of(
                Arguments.of("127.0.0.1/32", "127.0.0.1", true),
                Arguments.of("127.0.0.1/32", "127.0.0.2", false),
                Arguments.of("192.168.0.0/24", "192.168.0.1", true),
                Arguments.of("192.168.0.0/24", "192.168.0.2", true),
                Arguments.of("192.168.0.0/24", "192.168.0.200", true),
                Arguments.of("192.168.0.0/24", "192.168.0.255", true),
                Arguments.of("192.168.0.0/24", "192.168.1.1", false),
                Arguments.of("192.168.10.0/24", "192.168.10.1", true),
                Arguments.of("192.168.10.0/24", "192.168.10.2", true),
                Arguments.of("192.168.10.0/24", "192.168.10.200", true),
                Arguments.of("192.168.10.0/24", "192.168.10.255", true),
                Arguments.of("192.168.10.0/24", "192.168.20.1", false),
                Arguments.of("192.168.0.0/16", "192.168.10.1", true),
                Arguments.of("192.168.0.0/16", "192.168.10.2", true),
                Arguments.of("192.168.0.0/16", "192.168.10.200", true),
                Arguments.of("192.168.0.0/16", "192.168.10.255", true),
                Arguments.of("192.168.0.0/16", "192.168.20.1", true),
                Arguments.of("192.168.0.0/16", "192.160.20.1", false)
        );
    }
}
