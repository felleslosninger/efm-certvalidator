package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.CriticalExtensionRecognizedType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.CriticalExtensionRecognizedRule;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class CriticalExtensionRecognizedRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return CriticalExtensionRecognizedType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        CriticalExtensionRecognizedType rule = (CriticalExtensionRecognizedType) o;

        return new CriticalExtensionRecognizedRule(rule.getValue().toArray(new String[rule.getValue().size()]));
    }
}
