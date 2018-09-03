package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.CrlCache;
import no.difi.certvalidator.api.CrlFetcher;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.ValidatorRuleParser;
import no.difi.certvalidator.jaxb.CRLType;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.rule.CRLRule;
import no.difi.certvalidator.util.SimpleCachingCrlFetcher;
import no.difi.certvalidator.util.SimpleCrlCache;
import org.kohsuke.MetaInfServices;

import java.util.Map;

/**
 * @author erlend
 */
@MetaInfServices
public class CRLRuleParser implements ValidatorRuleParser {

    @Override
    public boolean supports(Class cls) {
        return CRLType.class.equals(cls);
    }

    @Override
    public ValidatorRule parse(Object o, Map<String, Object> objectStorage) throws ValidatorParsingException {
        if (!objectStorage.containsKey("crlFetcher") && !objectStorage.containsKey("crlCache"))
            objectStorage.put("crlCache", new SimpleCrlCache());

        if (!objectStorage.containsKey("crlFetcher"))
            objectStorage.put("crlFetcher", new SimpleCachingCrlFetcher((CrlCache) objectStorage.get("crlCache")));

        return new CRLRule((CrlFetcher) objectStorage.get("crlFetcher"));

    }
}
