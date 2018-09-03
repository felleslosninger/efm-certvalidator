package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.ClassType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class ClassRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return ClassType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        ClassType classType = (ClassType) o;

        try {
            return (ValidatorRule) Class.forName(classType.getValue()).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new ValidatorParsingException(
                    String.format("Unable to load rule '%s'.", classType.getValue()), e);
        }
    }
}
