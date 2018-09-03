package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.ValidatorReferenceType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class ValidatorReferenceRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return ValidatorReferenceType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        ValidatorReferenceType rule = (ValidatorReferenceType) o;

        String identifier = String.format("#validator::%s", rule.getValue());
        if (!objectStorage.containsKey(identifier))
            throw new ValidatorParsingException(String.format("Unable to find validator '%s'.", rule.getValue()));

        return (ValidatorRule) objectStorage.get(identifier);
    }
}
