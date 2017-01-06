package no.difi.certvalidator.extra;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.PrincipalNameProvider;
import no.difi.certvalidator.rule.PrincipalNameRule;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Implementation of fetching of Norwegian organization number from certificates.
 * <p/>
 * Use of organization numbers in certificates is defines here:
 * http://www.regjeringen.no/upload/FAD/Vedlegg/IKT-politikk/SEID_Leveranse_1_-_v1.02.pdf (page 24)
 */
public class NorwegianOrganizationNumberRule extends PrincipalNameRule {

    private static final Pattern patternSerialnumber = Pattern.compile("^[0-9]{9}$");
    private static final Pattern patternOrganizationName = Pattern.compile("^.+\\-\\W*([0-9]{9})$");

    public NorwegianOrganizationNumberRule() {
        this(new PrincipalNameProvider<String>() {
            @Override
            public boolean validate(String value) {
                return true;
            }
        });
    }

    public NorwegianOrganizationNumberRule(PrincipalNameProvider<String> provider) {
        super(provider);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        NorwegianOrganization organization = extractNumber(certificate);
        if (organization != null)
            if (provider.validate(organization.getNumber()))
                return;

        throw new FailedValidationException("Organization number not detected.");
    }

    /**
     * Extracts organization number using functionality provided by PrincipalNameValidator.
     *
     * @param certificate Certificate subject to validation.
     * @return Organization number found in certificate, null if not found.
     * @throws CertificateValidationException
     */
    public static NorwegianOrganization extractNumber(X509Certificate certificate) throws CertificateValidationException {
        try {
            // Fetch organization name.
            List<String> name = extract(getSubject(certificate), "O");

            //matches "C=NO,ST=AKERSHUS,L=FORNEBUVEIEN 1\\, 1366 LYSAKER,O=RF Commfides,SERIALNUMBER=399573952,CN=RF Commfides"
            for (String value : extract(getSubject(certificate), "SERIALNUMBER"))
                if (patternSerialnumber.matcher(value).matches())
                    return new NorwegianOrganization(value, name.isEmpty() ? null : name.get(0));

            //matches "CN=name, OU=None, O=organisasjon - 123456789, L=None, C=None"
            for (String value : extract(getSubject(certificate), "O")) {
                Matcher matcher = patternOrganizationName.matcher(value);
                if (matcher.matches())
                    return new NorwegianOrganization(matcher.group(1), name.get(0));
            }

            return null;
        } catch (CertificateEncodingException | NullPointerException e) {
            throw new CertificateValidationException(e.getMessage(), e);
        }
    }

    public static class NorwegianOrganization {
        private String number;
        private String name;

        public NorwegianOrganization(String number, String name) {
            this.number = number;
            this.name = name;
        }

        public String getNumber() {
            return number;
        }

        public String getName() {
            return name;
        }
    }
}
