package unifi_fail2ban;

import io.micronaut.configuration.picocli.PicocliRunner;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.env.Environment;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class UnifiFail2banCommandTest {

    @Test
    public void testWithCommandLineOption() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        System.setOut(new PrintStream(baos));

        try (ApplicationContext ctx = ApplicationContext.run(Environment.CLI, Environment.TEST)) {
            String[] args = new String[]{};
            PicocliRunner.run(UnifiFail2banCommand.class, ctx, args);
            final String output = baos.toString();
            assertTrue(output.contains("Done!!"));
        } finally {
            // unifi-fail2ban
            System.out.println(baos);
        }
    }
}
