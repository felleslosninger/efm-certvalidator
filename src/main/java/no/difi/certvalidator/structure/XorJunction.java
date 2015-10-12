package no.difi.certvalidator.structure;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Allows combining instances of validators using a limited set of logic.
 */
public class XorJunction extends AbstractJunction {

    private static final Logger logger = LoggerFactory.getLogger(XorJunction.class);

    public XorJunction(ValidatorRule... validatorRules) {
        super(validatorRules);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        List<CertificateValidationException> exceptions = new ArrayList<CertificateValidationException>();

        for (ValidatorRule validatorRule : validatorRules) {
            try {
                validatorRule.validate(certificate);
            } catch (CertificateValidationException e) {
                logger.debug(e.getMessage());
                exceptions.add(e);
            }
        }

        if (exceptions.size() != validatorRules.size() - 1) {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(String.format("Xor-junction failed with results (%s of %s):", exceptions.size(), validatorRules.size()));
            for (Exception e : exceptions)
                stringBuilder.append("\n* ").append(e.getMessage());

            logger.debug("{}\n({})", stringBuilder.toString(), certificate.getSerialNumber());
            throw new FailedValidationException(stringBuilder.toString());
        }
    }
}
