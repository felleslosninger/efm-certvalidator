package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.ValidatorRule;

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

    private List<ValidatorRule> validatorRules = new ArrayList<ValidatorRule>();

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

        return new Validator(
                new JunctionRule(JunctionRule.Kind.AND, validatorRules.toArray(
                        new ValidatorRule[validatorRules.size()])));
    }
}
