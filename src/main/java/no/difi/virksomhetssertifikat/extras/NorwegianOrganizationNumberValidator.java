package no.difi.virksomhetssertifikat.extras;

import no.difi.virksomhetssertifikat.PrincipalNameValidator;
import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Implementerer uthenting av orgnumber basert på http://www.regjeringen.no/upload/FAD/Vedlegg/IKT-politikk/SEID_Leveranse_1_-_v1.02.pdf side 24
 */
public class NorwegianOrganizationNumberValidator extends PrincipalNameValidator {

    private static Logger logger = LoggerFactory.getLogger(NorwegianOrganizationNumberValidator.class);

    private static Pattern patternSerialnumber = Pattern.compile("^[0-9]{9}$");
    private static Pattern patternOrganizationName = Pattern.compile("^.+\\-\\W*([0-9]{9})$");

    public NorwegianOrganizationNumberValidator(PrincipalNameProvider provider) {
        super(provider);
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        String value = extractNumber(certificate);
        if (value != null)
            if (provider.validate(value))
                return;

        logger.debug("Organization number not detected. ({})", certificate.getSerialNumber());
        throw new FailedValidationException("Organization number not detected.");
    }

    protected String extractNumber(X509Certificate certificate) throws CertificateValidationException {
        try {
            //matches "C=NO,ST=AKERSHUS,L=FORNEBUVEIEN 1\\, 1366 LYSAKER,O=RF Commfides,SERIALNUMBER=399573952,CN=RF Commfides"
            for (String value : extract(getSubject(certificate), "SERIALNUMBER"))
                if (patternSerialnumber.matcher(value).matches())
                    return value;

            //matches "CN=name, OU=None, O=organisasjon - 123456789, L=None, C=None"
            for (String value : extract(getSubject(certificate), "O")) {
                Matcher matcher = patternOrganizationName.matcher(value);
                if (matcher.matches())
                    return matcher.group(1);
            }
        } catch (CertificateEncodingException e) {
            logger.debug(e.getMessage());
            throw new CertificateValidationException(e.getMessage(), e);
        }

        return null;
    }
}
