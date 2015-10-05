package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidator;

import java.util.ArrayList;
import java.util.List;

/**
 * Builder for creation of validators.
 */
public class ValidatorBuilder {

    /**
     * Point of entry.
     *
     * @return Builder instance.
     */
    public static ValidatorBuilder newInstance() {
        return new ValidatorBuilder();
    }

    private List<CertificateValidator> certificateValidators = new ArrayList<>();

    private ValidatorBuilder() {
        // No action
    }

    /**
     * Append validator instance to validator.
     *
     * @param certificateValidator Configured validator.
     * @return Builder instance.
     */
    public ValidatorBuilder append(CertificateValidator certificateValidator) {
        certificateValidators.add(certificateValidator);
        return this;
    }

    /**
     * Generates a ValidatorHelper instance containing defined validator(s).
     *
     * @return Validator ready for use.
     */
    public ValidatorHelper build() {
        if (certificateValidators.size() == 1)
            return new ValidatorHelper(certificateValidators.get(0));

        return new ValidatorHelper(
                new SuiteValidator(certificateValidators.toArray(
                        new CertificateValidator[certificateValidators.size()])));
    }
}
