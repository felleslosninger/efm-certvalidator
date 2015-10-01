package no.difi.virksomhetssertifikat.util;

import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;

import java.util.Arrays;
import java.util.List;

/**
 * Validate principal name using a static list of values.
 */
public class SimplePrincipalNameProvider implements PrincipalNameProvider {

    private List<String> expected;

    public SimplePrincipalNameProvider(String... expected) {
        this.expected = Arrays.asList(expected);
    }

    @Override
    public boolean validate(String name) {
        return expected.contains(name);
    }
}
