package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.DummyType;
import no.difi.certvalidator.rule.DummyRule;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class DummyRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return DummyType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) {
        DummyType dummyType = (DummyType) o;

        return new DummyRule(dummyType.getValue());
    }
}

