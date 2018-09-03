package no.difi.certvalidator.parser;

import no.difi.certvalidator.Validator;
import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.Order;
import no.difi.certvalidator.api.ValidatorRecipeParser;
import no.difi.certvalidator.jaxb.*;
import no.difi.certvalidator.lang.ValidatorParsingException;
import no.difi.certvalidator.util.KeyStoreCertificateBucket;
import no.difi.certvalidator.util.SimpleCertificateBucket;
import org.kohsuke.MetaInfServices;

import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * @author erlend
 */
@Order(200)
@MetaInfServices
public class ValidatorBucketsLoader implements ValidatorRecipeParser {

    @Override
    public void parse(ValidatorRecipe recipe, Map<String, Object> objectStorage) throws ValidatorParsingException {
        try {
            for (CertificateBucketType certificateBucketType : recipe.getCertificateBucket()) {
                SimpleCertificateBucket certificateBucket = new SimpleCertificateBucket();

                for (Object o : certificateBucketType.getCertificateOrCertificateReferenceOrCertificateStartsWith()) {
                    if (o instanceof CertificateType) {
                        certificateBucket.add(Validator.getCertificate(((CertificateType) o).getValue()));
                    } else if (o instanceof CertificateReferenceType) {
                        CertificateReferenceType c = (CertificateReferenceType) o;
                        for (X509Certificate certificate :
                                getKeyStore(c.getKeyStore(), objectStorage).toSimple(c.getValue()))
                            certificateBucket.add(certificate);
                    } else if (o instanceof CertificateStartsWithType) {
                        CertificateStartsWithType c = (CertificateStartsWithType) o;
                        for (X509Certificate certificate :
                                getKeyStore(c.getKeyStore(), objectStorage).startsWith(c.getValue()))
                            certificateBucket.add(certificate);
                    }
                }

                objectStorage.put(String.format("#bucket::%s", certificateBucketType.getName()), certificateBucket);
            }
        } catch (CertificateValidationException e) {
            throw new ValidatorParsingException(e.getMessage(), e);
        }
    }

    private static KeyStoreCertificateBucket getKeyStore(String name, Map<String, Object> objectStorage) {
        return (KeyStoreCertificateBucket) objectStorage.get(
                String.format("#keyStore::%s", name == null ? "default" : name));
    }
}
