package no.difi.certvalidator.structure;

import no.difi.certvalidator.api.ValidatorRule;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class Junction {

    public static AndJunction and(ValidatorRule... validatorRules) {
        return new AndJunction(validatorRules);
    }

    public static OrJunction or(ValidatorRule... validatorRules) {
        return new OrJunction(validatorRules);
    }

    public static XorJunction xor(ValidatorRule... validatorRules) {
        return new XorJunction(validatorRules);
    }

    Junction() {
        // No action
    }
}
