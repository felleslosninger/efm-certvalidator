package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.PrincipalNameProvider;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.PrincipleNameType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.PrincipalNameRule;
import no.difi.certvalidator.util.SimplePrincipalNameProvider;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class PrincipleNameRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return PrincipleNameType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        PrincipleNameType principleNameType = (PrincipleNameType) o;

        PrincipalNameProvider<String> principalNameProvider;
        if (principleNameType.getReference() != null)
            principalNameProvider = (PrincipalNameProvider<String>) objectStorage.get(principleNameType.getReference().getValue());
        else
            principalNameProvider = new SimplePrincipalNameProvider(principleNameType.getValue());

        return new PrincipalNameRule(
                principleNameType.getField(),
                principalNameProvider,
                principleNameType.getPrincipal() != null ?
                        PrincipalNameRule.Principal.valueOf(principleNameType.getPrincipal().toString()) : PrincipalNameRule.Principal.SUBJECT
        );
    }
}
