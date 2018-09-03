package no.difi.certvalidator.structure;

import no.difi.certvalidator.api.ValidatorRule;

import java.util.Arrays;
import java.util.List;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public interface Junction {

    static ValidatorRule and(ValidatorRule... validatorRules) {
        return and(Arrays.asList(validatorRules));
    }

    static ValidatorRule and(List<ValidatorRule> validatorRules) {
        if (validatorRules.size() == 1)
            return validatorRules.get(0);
        return new AndJunction(validatorRules);
    }

    static ValidatorRule or(ValidatorRule... validatorRules) {
        return or(Arrays.asList(validatorRules));
    }

    static ValidatorRule or(List<ValidatorRule> validatorRules) {
        if (validatorRules.size() == 1)
            return validatorRules.get(0);
        return new OrJunction(validatorRules);
    }

    static ValidatorRule xor(ValidatorRule... validatorRules) {
        return xor(Arrays.asList(validatorRules));
    }

    static ValidatorRule xor(List<ValidatorRule> validatorRules) {
        if (validatorRules.size() == 1)
            return validatorRules.get(0);
        return new XorJunction(validatorRules);
    }
}
