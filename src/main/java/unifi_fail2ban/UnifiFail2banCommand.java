package unifi_fail2ban;

import io.micronaut.configuration.picocli.MicronautFactory;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.ApplicationContextBuilder;
import io.micronaut.context.env.CommandLinePropertySource;
import io.micronaut.context.env.Environment;
import io.micronaut.core.annotation.Introspected;
import io.vavr.collection.Stream;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import unifi_fail2ban.model.Alert;
import unifi_fail2ban.model.AlertDetectionService;
import unifi_fail2ban.model.Firewall;
import unifi_fail2ban.unifi_api.FirewallGroup;
import unifi_fail2ban.unifi_api.IpsEvent;
import unifi_fail2ban.unifi_api.UnifiApiService;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;

@Slf4j
@Command(
        name = "unifi-fail2ban",
        description = "A tool to block IPs based on IPS events",
        mixinStandardHelpOptions = true
)
@Introspected(
        accessKind = Introspected.AccessKind.FIELD,
        visibility = Introspected.Visibility.DEFAULT,
        indexed = {
                @Introspected.IndexedAnnotation(annotation = MappedProperty.class, member = "value"),
                @Introspected.IndexedAnnotation(annotation = CommandLine.Option.class, member = "names"),
        }
)
public class UnifiFail2banCommand implements Callable<Integer> {

    public static final int SUCCESS_EXIT_CODE = 0;
    public static final int ERROR_EXIT_CODE = 1;

    @MappedProperty("unifi.host")
    @CommandLine.Option(names = {"-h", "--unifi-host"}, description = """
            Set the Unifi API host.
            This parameter can also be set via environment variable UNIFI_HOST.
            """,
            defaultValue = "localhost"
    )
    String unifiHost;

    @MappedProperty("unifi.site")
    @CommandLine.Option(names = {"-s", "--unifi-site"}, description = """
            Set the Unifi Network site.
            This parameter can also be set via environment variable UNIFI_SITE.
            """,
            defaultValue = "default"
    )
    String unifiSite;

    @MappedProperty("unifi.username")
    @CommandLine.Option(names = {"--unifi-username"}, description = """
            Set the Unifi Network username to authenticate against the API.
            This parameter can also be set via environment variable UNIFI_USERNAME.
            Please consider setting this parameter on the environment because commands are typically logged.
            """,
            defaultValue = "admin"
    )
    String unifiUsername;

    @MappedProperty("unifi.password")
    @CommandLine.Option(names = {"--unifi-password"}, description = """
            Set the Unifi Network password to authenticate against the API.
            This parameter can also be set via environment variable UNIFI_PASSWORD.
            Please consider setting this parameter on the environment because commands are typically logged.
            """)
    String unifiPassword;

    @MappedProperty("unifi.firewall-group-name")
    @CommandLine.Option(names = {"-g", "--unifi-firewall-group"}, description = """
            Set the Unifi Network Firewall Group name. This group is where blocked IPs will be added.
            This parameter can also be set via environment variable UNIFI_FIREWALL_GROUP_NAME.
            """,
            defaultValue = "unifi-fail2ban"
    )
    String unifiFirewallGroupName;

    @MappedProperty("detect.allowed-cidrs")
    @CommandLine.Option(names = {"-a", "--allowed-cidrs"}, description = """
            Set a list of CIDRs (separated by commas) that will not be blocked even when they are the src IP in IPS events.
            This parameter can also be set via environment variable DETECT_ALLOWED_CIDRS.
            """,
            defaultValue = "",
            split = ","
    )
    List<String> detectAllowedSrcCidrs;

    @MappedProperty("detect.protected-cidrs")
    @CommandLine.Option(names = {"-c", "--protected-cidrs"}, description = """
            Set a list of CIDRs (separated by commas) that will be monitored as dst IPs in IPS events.
            When IPS events that target IPs in these CIDRs on the defined protected ports are found the src IPs of the traffic are blocked. 
            This parameter can also be set via environment variable DETECT_PROTECTED_CIDRS.
            """,
            defaultValue = "192.168.0.0/16",
            split = ","
    )
    List<String> detectProtectedCidrs;

    @MappedProperty("detect.protected-ports")
    @CommandLine.Option(names = {"-p", "--protected-ports"}, description = """
            Set a list of ports (separated by commas) that will be monitored as dst port in IPS events.
            When IPS events that target these ports on the defined protected IPs are found the src IPs of the traffic are blocked. 
            This parameter can also be set via environment variable DETECT_PROTECTED_PORTS.
            """,
            defaultValue = "22,80,443",
            split = ","
    )
    List<Integer> detectProtectedPorts;

    @CommandLine.Option(names = {"--print-configuration"}, description = """
            Have the tool print its configuration instead of running the detection.
            """,
            defaultValue = "false"
    )
    boolean printConfiguration = false;

    @Inject
    UnifiApiService apiService;

    @Inject
    AlertDetectionService detectionService;

    @Inject
    DetectionConfiguration detectionConfiguration;

    @Inject
    UnifiConfiguration unifiConfiguration;

    @Inject
    ConfigurationService configurationService;

    public static void main(String[] args) {
        int exitCode = execute(args);
        System.exit(exitCode);
    }

    protected static int execute(String[] args) {
        io.micronaut.core.cli.CommandLine commandLine = io.micronaut.core.cli.CommandLine.parse(args);
        CommandLinePropertySource commandLinePropertySource = new CommandLinePropertySource(commandLine);
        UnifiedCommandOptionsPropertySource unifiedCommandOptionsPropertySource = new UnifiedCommandOptionsPropertySource(commandLine);
        final ApplicationContextBuilder contextBuilder = ApplicationContext.builder(UnifiFail2banCommand.class, Environment.CLI)
                                                                           .propertySources(commandLinePropertySource, unifiedCommandOptionsPropertySource);

        try (ApplicationContext context = contextBuilder.start()) {
            return new CommandLine(
                    UnifiFail2banCommand.class,
                    new MicronautFactory(context)
            ).setCaseInsensitiveEnumValuesAllowed(true)
             .setUsageHelpAutoWidth(true)
             .execute(args);
        }
    }

    public Integer call() {

        configurationService.printConfiguration();
        if (printConfiguration) {
            return SUCCESS_EXIT_CODE;
        }

        try {
            final String username = unifiConfiguration.username();
            log.info("Authenticating user {} to Unifi at {}", username, unifiHost);
            apiService.login(username, unifiConfiguration.password());

            final FirewallGroup initialFirewallGroup = getOrCreateFirewallGroup();
            log.info("Firewall group has {} members", initialFirewallGroup.memberCount());
            final Stream<IpsEvent> ipsEvents = getIpsEvents();
            log.info("Retrieved {} IPS events from Unifi", ipsEvents.size());

            final Firewall initialFirewall = ModelAntiCorruptionLayer.convert(initialFirewallGroup);
            final Stream<Alert> alerts = ModelAntiCorruptionLayer.convert(ipsEvents);
            final Stream<String> matchedSrcIps = detectionService.scan(alerts).map(Alert::srcIp);
            log.info("Matched {} src IPs from IPS events", matchedSrcIps.size());
            final Firewall updatedFirewall = initialFirewall.blockIps(matchedSrcIps);

            final FirewallGroup updatedFirewallGroup = ModelAntiCorruptionLayer.convert(initialFirewallGroup, updatedFirewall);
            log.info("Firewall group will have {} members", updatedFirewallGroup.members().size());
            apiService.updateFirewallGroup(updatedFirewallGroup);
            log.info("Done!");

            return SUCCESS_EXIT_CODE;
        } catch (Exception e) {
            log.error("An exception was caught during command execution: {}", e.getMessage());
            log.debug("Full exception: ", e);

            return ERROR_EXIT_CODE;
        }

    }

    private Stream<IpsEvent> getIpsEvents() {
        return Stream.ofAll(apiService.listIpsAlerts());
    }

    private FirewallGroup getOrCreateFirewallGroup() {
        final String firewallGroupName = unifiConfiguration.firewallGroupName();
        log.debug("Looking for firewall group named {}", firewallGroupName);
        final Stream<FirewallGroup> firewallGroups = Stream.ofAll(apiService.listFirewallGroups())
                                                           .filter(firewallGroup -> Objects.equals(firewallGroup.name(), firewallGroupName));
        log.debug("Found {} firewall groups", firewallGroups.size());
        return firewallGroups.headOption()
                             .getOrElse(() -> {
                                 log.info("Creating firewall group named {}", firewallGroupName);
                                 return apiService.createFirewallGroup(firewallGroupName);
                             });
    }
}
