package no.difi.virksomhetssertifikat.structure;

import no.difi.virksomhetssertifikat.api.CertificateValidationException;
import no.difi.virksomhetssertifikat.api.ValidatorRule;
import no.difi.virksomhetssertifikat.api.FailedValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class Junction implements ValidatorRule {

    private static final Logger logger = LoggerFactory.getLogger(Junction.class);

    public static Junction and(ValidatorRule... validatorRules) {
        return new Junction(Kind.AND, validatorRules);
    }

    public static Junction or(ValidatorRule... validatorRules) {
        return new Junction(Kind.OR, validatorRules);
    }

    public static Junction xor(ValidatorRule... validatorRules) {
        return new Junction(Kind.XOR, validatorRules);
    }

    private Kind kind;
    private ValidatorRule[] validatorRules;

    public Junction(Kind kind, ValidatorRule... validatorRules) {
        this.kind = kind;
        this.validatorRules = validatorRules;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        switch (kind) {
            case AND:
                validateAND(certificate);
                break;

            case OR:
                validateOR(certificate);
                break;

            case XOR:
                validateXOR(certificate);
                break;

            default:
                throw new CertificateValidationException("Kind of junction not found.");
        }
    }

    private void validateAND(X509Certificate certificate) throws CertificateValidationException {
        for (ValidatorRule validatorRule : validatorRules)
            validatorRule.validate(certificate);
    }

    private void validateOR(X509Certificate certificate) throws CertificateValidationException {
        List<CertificateValidationException> exceptions = new ArrayList<CertificateValidationException>();

        for (ValidatorRule validatorRule : validatorRules) {
            try {
                validatorRule.validate(certificate);
                return;
            } catch (CertificateValidationException e) {
                exceptions.add(e);
            }
        }

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Or-junction failed with results:");
        for (Exception e : exceptions)
            stringBuilder.append("\n* ").append(e.getMessage());

        logger.debug("{}\n({})", stringBuilder.toString(), certificate.getSerialNumber());
        throw new FailedValidationException(stringBuilder.toString());
    }

    private void validateXOR(X509Certificate certificate) throws CertificateValidationException {
        List<CertificateValidationException> exceptions = new ArrayList<CertificateValidationException>();

        for (ValidatorRule validatorRule : validatorRules) {
            try {
                validatorRule.validate(certificate);
            } catch (CertificateValidationException e) {
                logger.debug(e.getMessage());
                exceptions.add(e);
            }
        }

        if (exceptions.size() != validatorRules.length - 1) {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(String.format("Xor-junction failed with results (%s of %s):", exceptions.size(), validatorRules.length));
            for (Exception e : exceptions)
                stringBuilder.append("\n* ").append(e.getMessage());

            logger.debug("{}\n({})", stringBuilder.toString(), certificate.getSerialNumber());
            throw new FailedValidationException(stringBuilder.toString());
        }
    }

    /**
     * Defines what kind of logic to use in JunctionValidator.
     */
    public enum Kind {
        AND, OR, XOR
    }
}
