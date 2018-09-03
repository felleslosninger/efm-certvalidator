package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.RuleReferenceType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class RuleReferenceRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return RuleReferenceType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        RuleReferenceType ruleReferenceType = (RuleReferenceType) o;

        if (!objectStorage.containsKey(ruleReferenceType.getValue()))
            throw new ValidatorParsingException(
                    String.format("Rule for '%s' not found.", ruleReferenceType.getValue()));

        return (ValidatorRule) objectStorage.get(ruleReferenceType.getValue());

    }
}
