package no.difi.certvalidator.util;

import no.difi.certvalidator.api.Property;
import no.difi.certvalidator.api.Report;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author erlend
 */
public class SimpleReport implements Report {

    private final Map<Property, Object> values;

    public static Report newInstance() {
        return new SimpleReport();
    }

    private SimpleReport() {
        this(new HashMap<Property, Object>());
    }

    private SimpleReport(Map<Property, Object> values) {
        this.values = values;
    }

    @Override
    public <T> boolean contains(Property<T> key) {
        return values.containsKey(key);
    }

    @Override
    public <T> void set(Property<T> key, T value) {
        values.put(key, value);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> T get(Property<T> key) {
        return (T) values.get(key);
    }

    @Override
    public Set<Property> keys() {
        return values.keySet();
    }

    @Override
    public Report copy() {
        return new SimpleReport(new HashMap<>(values));
    }
}
