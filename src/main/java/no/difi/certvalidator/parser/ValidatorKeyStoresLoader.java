package no.difi.certvalidator.parser;

import no.difi.certvalidator.api.CertificateBucketException;
import no.difi.certvalidator.api.Order;
import no.difi.certvalidator.api.ValidatorRecipeParser;
import no.difi.certvalidator.jaxb.KeyStoreType;
import no.difi.certvalidator.jaxb.ValidatorRecipe;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.util.KeyStoreCertificateBucket;
import org.kohsuke.MetaInfServices;

import java.io.ByteArrayInputStream;
import java.util.Map;

/**
 * @author erlend
 */
@Order(100)
@MetaInfServices
public class ValidatorKeyStoresLoader implements ValidatorRecipeParser {

    @Override
    public void parse(ValidatorRecipe recipe, Map<String, Object> objectStorage) throws ValidatorParsingException {
        try {
            for (KeyStoreType keyStoreType : recipe.getKeyStore()) {
                objectStorage.put(
                        String.format("#keyStore::%s", keyStoreType.getName() == null ? "default" : keyStoreType.getName()),
                        new KeyStoreCertificateBucket(
                                new ByteArrayInputStream(keyStoreType.getValue()),
                                keyStoreType.getPassword()
                        )
                );
            }
        } catch (CertificateBucketException e) {
            throw new ValidatorParsingException(e.getMessage(), e);
        }
    }
}
