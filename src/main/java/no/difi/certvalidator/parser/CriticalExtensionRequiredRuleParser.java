package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.CriticalExtensionRequiredType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.CriticalExtensionRequiredRule;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class CriticalExtensionRequiredRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return CriticalExtensionRequiredType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        CriticalExtensionRequiredType rule = (CriticalExtensionRequiredType) o;

        return new CriticalExtensionRequiredRule(rule.getValue().toArray(new String[rule.getValue().size()]));
    }
}
