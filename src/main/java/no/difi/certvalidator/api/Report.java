package no.difi.certvalidator.api;

import java.util.Set;

/**
 * @author erlend
 */
public interface Report {

    <T> boolean contains(Property<T> key);

    <T> void set(Property<T> key, T value);

    <T> T get(Property<T> key);

    Set<Property> keys();

    Report copy();

}
