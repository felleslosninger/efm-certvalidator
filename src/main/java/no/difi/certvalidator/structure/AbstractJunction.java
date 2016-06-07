package no.difi.certvalidator.structure;

import no.difi.certvalidator.api.ValidatorRule;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public abstract class AbstractJunction implements ValidatorRule {

    protected List<ValidatorRule> validatorRules = new ArrayList<>();

    public AbstractJunction(ValidatorRule... validatorRules) {
        addRule(validatorRules);
    }

    public AbstractJunction addRule(ValidatorRule... validatorRules) {
        this.validatorRules.addAll(Arrays.asList(validatorRules));
        return this;
    }
}
