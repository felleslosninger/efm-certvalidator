package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

public class PrincipalNameValidator implements CertificateValidator {

    private static Logger logger = LoggerFactory.getLogger(PrincipalNameValidator.class);

    private String field;
    private PrincipalNameProvider provider;
    private Principal principal;

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

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        X500Principal current = null;
        switch (principal) {
            case SUBJECT:
                current = certificate.getSubjectX500Principal();
                break;

            case ISSUER: {
                current = certificate.getIssuerX500Principal();
                break;
            }
        }

        if (!provider.validate(extract(current, field))) {
            logger.debug("Validation of subject principal({}) failed. ({})", field, certificate.getSerialNumber());
            throw new FailedValidationException("");
        }
    }

    protected String extract(X500Principal principal, String field) {
        if (field == null)
            return principal.getName();

        // TODO Extract
        // X500Name.asX500Name(cert.getSubjectX500Principal()).get
        return null;
    }

    public enum Principal {
        SUBJECT, ISSUER
    }
}
