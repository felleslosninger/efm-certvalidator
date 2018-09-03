package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.ExpirationType;
import no.difi.certvalidator.rule.ExpirationRule;
import no.difi.certvalidator.rule.ExpirationSoonRule;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class ExpirationRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return ExpirationType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) {
        ExpirationType expirationType = (ExpirationType) o;

        if (expirationType.getMillis() == null)
            return new ExpirationRule();
        else
            return new ExpirationSoonRule(expirationType.getMillis());

    }
}
