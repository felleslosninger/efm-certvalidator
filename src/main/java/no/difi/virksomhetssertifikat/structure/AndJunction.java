package no.difi.virksomhetssertifikat.structure;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;

import java.security.cert.X509Certificate;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class AndJunction extends AbstractJunction {

    public AndJunction(ValidatorRule... validatorRules) {
        super(validatorRules);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        for (ValidatorRule validatorRule : validatorRules)
            validatorRule.validate(certificate);
    }
}
