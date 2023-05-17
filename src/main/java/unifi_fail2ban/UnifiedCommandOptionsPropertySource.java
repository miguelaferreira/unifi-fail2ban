package unifi_fail2ban;

import io.micronaut.context.env.MapPropertySource;
import io.micronaut.context.env.SystemPropertiesPropertySource;
import io.micronaut.core.beans.BeanIntrospection;
import io.micronaut.core.beans.BeanProperty;
import io.micronaut.core.cli.CommandLine;
import io.vavr.Tuple;
import io.vavr.Tuple2;
import io.vavr.collection.Stream;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Slf4j
public class UnifiedCommandOptionsPropertySource extends MapPropertySource {

    public static final int POSITION = SystemPropertiesPropertySource.POSITION + 100;

    /**
     * The name of the property source.
     */
    public static final String NAME = "consolidated";
    public static final String REGEX_MATCH_INITIAL_DASHES = "^-[-]*";
    public static final String EMPTY_STRING = "";

    /**
     * Construct the CommandLinePropertySource from properties passed from command line.
     *
     * @param commandLine Represents the parsed command line options.
     */
    public UnifiedCommandOptionsPropertySource(CommandLine commandLine) {
        super(NAME, resolveValues(commandLine));
    }

    @Override
    public int getOrder() {
        return POSITION;
    }

    private static Map<String, Object> resolveValues(CommandLine commandLine) {
        final BeanIntrospection<UnifiFail2banCommand> introspection = BeanIntrospection.getIntrospection(UnifiFail2banCommand.class);

        if (commandLine == null) {
            return Collections.emptyMap();
        }

        final Stream<Tuple2<String, String>> propertyAndCliOptionNames =
                Stream.ofAll(introspection.getBeanProperties())
                      .filter(p -> p.hasDeclaredAnnotation(MappedProperty.class))
                      .map(p -> Tuple.of(getMappedValue(p), getOptionNames(p)))
                      .filter(tuple -> tuple._1.isPresent() && tuple._2.isPresent())
                      .map(tuple -> Tuple.of(tuple._1.get(), tuple._2.get()));

        final Map<String, Object> undeclaredOptions = commandLine.getUndeclaredOptions();
        return propertyAndCliOptionNames.map(tuple -> lookupPropertyValues(undeclaredOptions, tuple))
                                        .filter(tuple -> tuple._2 != null)
                                        .map(UnifiedCommandOptionsPropertySource::logConsolidatedProperties)
                                        .toJavaMap(Function.identity());
    }

    private static Tuple2<String, Object> logConsolidatedProperties(Tuple2<String, Object> tuple) {
        log.debug("Setting {} = {}", tuple._1, tuple._2);
        return tuple;
    }

    private static Tuple2<String, Object> lookupPropertyValues(Map<String, Object> undeclaredOptions, Tuple2<String, String> tuple) {
        return tuple.map2(cliOptionName -> lookupPropertyValue(undeclaredOptions, cliOptionName));
    }

    private static Object lookupPropertyValue(Map<String, Object> undeclaredOptions, String cliOptionName) {
        final String key = cliOptionName.replaceAll(REGEX_MATCH_INITIAL_DASHES, EMPTY_STRING);
        final Object value = undeclaredOptions.get(key);
        log.trace("Looked up {} = {}", cliOptionName, value);
        return value;
    }

    private static Optional<String> getOptionNames(BeanProperty<UnifiFail2banCommand, Object> p) {
        return p.getValue(picocli.CommandLine.Option.class, "names", String[].class)
                .map(array -> array.length > 0 ? array[0] : null);
    }

    private static Optional<String> getMappedValue(BeanProperty<UnifiFail2banCommand, Object> p) {
        return p.stringValue(MappedProperty.class);
    }
}
