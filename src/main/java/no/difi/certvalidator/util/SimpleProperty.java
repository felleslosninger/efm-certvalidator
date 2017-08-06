package no.difi.certvalidator.util;

import no.difi.certvalidator.api.Property;

/**
 * @author erlend
 */
public class SimpleProperty<T> implements Property<T> {

    public static <T> Property<T> create() {
        return new SimpleProperty<>();
    }

    private SimpleProperty() {
        // No action.
    }
}
