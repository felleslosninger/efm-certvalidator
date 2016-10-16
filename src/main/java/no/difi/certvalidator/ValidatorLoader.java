package no.difi.certvalidator;

import no.difi.certvalidator.lang.ValidatorParsingException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class ValidatorLoader {

    private Map<String, Object> objectStorage = new HashMap<>();

    public static ValidatorLoader newInstance() {
        return new ValidatorLoader();
    }

    private ValidatorLoader() {

    }

    public ValidatorLoader put(String key, Object value) {
        objectStorage.put(key, value);

        return this;
    }

    public ValidatorGroup build(Path path) throws IOException, ValidatorParsingException {
        try (InputStream inputStream = Files.newInputStream(path)) {
            return build(inputStream);
        }
    }

    public ValidatorGroup build(InputStream inputStream) throws ValidatorParsingException {
        return ValidatorLoaderParser.parse(inputStream, new HashMap<>(objectStorage));
    }
}
