package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Validator using defined logic to validate content in principal name of subject or issuer.
 */
public class PrincipalNameValidator implements CertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(PrincipalNameValidator.class);

    protected String field;
    protected PrincipalNameProvider provider;
    protected Principal principal;

    public PrincipalNameValidator(PrincipalNameProvider provider) {
        this(null, provider, Principal.SUBJECT);
    }

    public PrincipalNameValidator(PrincipalNameProvider provider, Principal principal) {
        this(null, provider, principal);
    }

    public PrincipalNameValidator(String field, PrincipalNameProvider provider) {
        this(field, provider, Principal.SUBJECT);
    }

    public PrincipalNameValidator(String field, PrincipalNameProvider provider, Principal principal) {
        this.field = field;
        this.provider = provider;
        this.principal = principal;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        try {
            X500Name current = null;
            switch (principal) {
                case SUBJECT:
                    current = getSubject(certificate);
                    break;

                case ISSUER:
                    current = getIssuer(certificate);
                    break;
            }

            for (String value : extract(current, field))
                if (provider.validate(value))
                    return;

            logger.debug("Validation of subject principal({}) failed. ({})", field, certificate.getSerialNumber());
            throw new FailedValidationException(String.format("Validation of subject principal(%s) failed.", field));
        } catch (CertificateEncodingException e) {
            logger.debug("Unable to fetch principal. ({})", certificate.getSerialNumber());
            throw new FailedValidationException("Unable to fetch principal.", e);
        }
    }

    protected X500Name getIssuer(X509Certificate certificate) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(certificate).getIssuer();
    }

    protected X500Name getSubject(X509Certificate certificate) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(certificate).getSubject();
    }

    @SuppressWarnings("all")
    protected List<String> extract(X500Name principal, String field) {
        if (field == null)
            return Arrays.asList(principal.toString());

        RFC4519Style.INSTANCE.attrNameToOID(field);

        List<String> values = new ArrayList<>();
        for (RDN rdn : principal.getRDNs(RFC4519Style.INSTANCE.attrNameToOID(field)))
            for (AttributeTypeAndValue value : rdn.getTypesAndValues())
                values.add(value.getValue().toString());

        return values;
    }

    public enum Principal {
        SUBJECT, ISSUER
    }
}
