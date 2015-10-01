package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidator;

/**
 * Combine multiple validators into one validator.
 */
public class SuiteValidator extends JunctionValidator {
    public SuiteValidator(CertificateValidator... certificateValidators) {
        super(Kind.AND, certificateValidators);
    }
}
