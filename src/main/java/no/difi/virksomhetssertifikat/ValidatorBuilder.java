package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidator;

import java.util.ArrayList;
import java.util.List;

public class ValidatorBuilder {

    public static ValidatorBuilder newInstance() {
        return new ValidatorBuilder();
    }

    private List<CertificateValidator> certificateValidators = new ArrayList<>();

    private ValidatorBuilder() {
        // No action
    }

    public ValidatorBuilder append(CertificateValidator certificateValidator) {
        certificateValidators.add(certificateValidator);
        return this;
    }

    public ValidatorHelper build() {
        if (certificateValidators.size() == 1)
            return new ValidatorHelper(certificateValidators.get(0));

        CertificateValidator[] vals = new CertificateValidator[certificateValidators.size()];
        certificateValidators.toArray(vals);
        return new ValidatorHelper(new SuiteValidator(vals));
    }
}
