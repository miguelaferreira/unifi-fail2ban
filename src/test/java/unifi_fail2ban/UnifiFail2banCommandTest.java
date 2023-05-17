package unifi_fail2ban;

import io.micronaut.configuration.picocli.PicocliRunner;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.env.Environment;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static unifi_fail2ban.UnifiFail2banCommand.SUCCESS_EXIT_CODE;

public class UnifiFail2banCommandTest {

    @Test
    public void testWithCommandLineOption() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        try (ApplicationContext ctx = ApplicationContext.run(Environment.CLI, Environment.TEST)) {
            String[] args = new String[]{"--unifi-username", "username", "--unifi-password", "password"};
            PicocliRunner.call(UnifiFail2banCommand.class, ctx, args);
            Assertions.assertThat(baos.toString())
                      .contains("Authenticating user admin to Unifi at localhost")
                      .contains("Connection refused");
        }
    }

    @Test
    void debugCommandOptions() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        final int exitCode = UnifiFail2banCommand.execute(new String[]{
                "--print-configuration",
                "-h", "unifi-host",
                "-s", "unifi-site",
                "--unifi-username", "username",
                "--unifi-password", "password",
                "-g", "unifi-firewall-group-name",
                "-a", "192.168.3.0/24",
                "-c", "192.168.1.1/32,192.168.1.2/32",
                "-p", "21,80",
        });

        Assertions.assertThat(exitCode)
                  .as("exit code should be success")
                  .isEqualTo(SUCCESS_EXIT_CODE);

        Assertions.assertThat(baos.toString())
                  .contains("Username: username")
                  .contains("Password: not empty")
                  .contains("Firewall group name: unifi-firewall-group-name")
                  .contains("Protected Ports: [21, 80]")
                  .contains("Protected Cidrs: [192.168.1.1/32, 192.168.1.2/32]")
                  .contains("Allowed Cidrs: [192.168.3.0/24]");
    }
}
