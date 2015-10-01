package no.difi.virksomhetssertifikat;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.CertificateValidator;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class JunctionValidator implements CertificateValidator {

    private Kind kind;
    private CertificateValidator[] certificateValidators;

    public JunctionValidator(Kind kind, CertificateValidator... certificateValidators) {
        this.kind = kind;
        this.certificateValidators = certificateValidators;
    }

    @Override
    public void validate(X509Certificate cert) throws CertificateValidationException {
        switch (kind) {
            case AND:
                validateAND(cert);
                break;

            case OR:
                validateOR(cert);
                break;
        }
    }

    private void validateAND(X509Certificate certificate) throws CertificateValidationException {
        for (CertificateValidator certificateValidator : certificateValidators)
            certificateValidator.validate(certificate);
    }

    private void validateOR(X509Certificate certificate) throws CertificateValidationException {
        List<CertificateValidationException> exceptions = new ArrayList<>();

        for (CertificateValidator certificateValidator : certificateValidators) {
            try {
                certificateValidator.validate(certificate);
                return;
            } catch (CertificateValidationException e) {
                exceptions.add(e);
            }
        }

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Or-junction failed with results:");
        for (Exception e : exceptions)
            stringBuilder.append("\n* ").append(e.getMessage());

        throw new CertificateValidationException(stringBuilder.toString());
    }

    public enum Kind {
        AND, OR
    }
}
