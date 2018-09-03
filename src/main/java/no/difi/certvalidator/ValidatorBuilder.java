package no.difi.certvalidator;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.structure.Junction;

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

    private List<ValidatorRule> validatorRules = new ArrayList<>();

    private ValidatorBuilder() {
        // No action
    }

    /**
     * Append validator instance to validator.
     *
     * @param validatorRule Configured validator.
     * @return Builder instance.
     */
    public ValidatorBuilder addRule(ValidatorRule validatorRule) {
        return add(validatorRule);
    }

    /**
     * Append validator instance to validator.
     *
     * @param validatorRule Configured validator.
     * @return Builder instance.
     */
    public ValidatorBuilder add(ValidatorRule validatorRule) {
        validatorRules.add(validatorRule);
        return this;
    }

    /**
     * Generates a ValidatorHelper instance containing defined validator(s).
     *
     * @return Validator ready for use.
     */
    public Validator build() {
        if (validatorRules.size() == 1)
            return new Validator(validatorRules.get(0));

        return new Validator(Junction.and(validatorRules));
    }
}
