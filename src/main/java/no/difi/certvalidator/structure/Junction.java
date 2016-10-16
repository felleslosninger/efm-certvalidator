package no.difi.certvalidator.structure;

import no.difi.certvalidator.api.ValidatorRule;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class Junction {

    public static ValidatorRule and(ValidatorRule... validatorRules) {
        if (validatorRules.length == 1)
            return validatorRules[0];
        return new AndJunction(validatorRules);
    }

    public static ValidatorRule or(ValidatorRule... validatorRules) {
        if (validatorRules.length == 1)
            return validatorRules[0];
        return new OrJunction(validatorRules);
    }

    public static ValidatorRule xor(ValidatorRule... validatorRules) {
        if (validatorRules.length == 1)
            return validatorRules[0];
        return new XorJunction(validatorRules);
    }

    Junction() {
        // No action
    }
}
