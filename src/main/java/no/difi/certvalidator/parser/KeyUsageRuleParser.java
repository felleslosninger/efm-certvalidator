package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.KeyUsageEnum;
import no.difi.certvalidator.jaxb.KeyUsageType;
import no.difi.certvalidator.rule.KeyUsageRule;
import no.difi.certvalidator.util.KeyUsage;
import org.kohsuke.MetaInfServices;

import java.util.List;
import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class KeyUsageRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return KeyUsageType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) {
        KeyUsageType keyUsageType = (KeyUsageType) o;

        List<KeyUsageEnum> keyUsages = keyUsageType.getIdentifier();
        KeyUsage[] result = new KeyUsage[keyUsages.size()];

        for (int i = 0; i < result.length; i++)
            result[i] = KeyUsage.valueOf(keyUsages.get(i).name());

        return new KeyUsageRule(result);
    }
}
