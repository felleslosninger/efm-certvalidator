package no.difi.certvalidator.util;

import no.difi.certvalidator.api.PrincipalNameProvider;

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

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean validate(String value) {
        return expected.contains(value);
    }
}
