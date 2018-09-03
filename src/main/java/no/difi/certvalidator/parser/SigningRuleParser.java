package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.SigningEnum;
import no.difi.certvalidator.jaxb.SigningType;
import no.difi.certvalidator.rule.SigningRule;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class SigningRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return SigningType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) {
        SigningType signingType = (SigningType) o;

        if (signingType.getType().equals(SigningEnum.SELF_SIGNED))
            return SigningRule.SelfSignedOnly();
        else
            return SigningRule.PublicSignedOnly();
    }
}
