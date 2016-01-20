package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.PrincipalNameProvider;
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
public class PrincipalNameRule implements ValidatorRule {

    private static final Logger logger = LoggerFactory.getLogger(PrincipalNameRule.class);

    protected String field;
    protected PrincipalNameProvider provider;
    protected Principal principal;

    public PrincipalNameRule(PrincipalNameProvider provider) {
        this(null, provider, Principal.SUBJECT);
    }

    public PrincipalNameRule(PrincipalNameProvider provider, Principal principal) {
        this(null, provider, principal);
    }

    public PrincipalNameRule(String field, PrincipalNameProvider provider) {
        this(field, provider, Principal.SUBJECT);
    }

    public PrincipalNameRule(String field, PrincipalNameProvider provider, Principal principal) {
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
            X500Name current;
            if (principal.equals(Principal.SUBJECT))
                current = getSubject(certificate);
            else
                current = getIssuer(certificate);

            for (String value : extract(current, field))
                if (provider.validate(value))
                    return;

            throw new FailedValidationException(String.format("Validation of subject principal(%s) failed.", field));
        } catch (CertificateEncodingException e) {
            logger.debug("Unable to fetch principal. ({})", certificate.getSerialNumber());
            throw new FailedValidationException("Unable to fetch principal.", e);
        }
    }

    protected static X500Name getIssuer(X509Certificate certificate) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(certificate).getIssuer();
    }

    protected static X500Name getSubject(X509Certificate certificate) throws CertificateEncodingException {
        return new JcaX509CertificateHolder(certificate).getSubject();
    }

    @SuppressWarnings("all")
    protected static List<String> extract(X500Name principal, String field) {
        if (field == null)
            return Arrays.asList(principal.toString());

        RFC4519Style.INSTANCE.attrNameToOID(field);

        List<String> values = new ArrayList<String>();
        for (RDN rdn : principal.getRDNs(RFC4519Style.INSTANCE.attrNameToOID(field)))
            for (AttributeTypeAndValue value : rdn.getTypesAndValues())
                values.add(value.getValue().toString());

        return values;
    }

    public enum Principal {
        SUBJECT, ISSUER
    }
}
