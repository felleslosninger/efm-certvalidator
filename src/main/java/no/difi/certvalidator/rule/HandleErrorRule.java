package no.difi.certvalidator.rule;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.FailedValidationException;
import no.difi.certvalidator.api.ValidatorRule;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Allows encapsulation of other validations rule, allowing errors to occur but not failed validation. May be useful
 * for encapsulation of CRLRule and other rules where use of external resources may cause validation to fail due to
 * unavailability of services.
 */
public class HandleErrorRule extends AbstractRule {

    private final List<ValidatorRule> validatorRules;

    public HandleErrorRule(ValidatorRule... validatorRules) {
        this(Arrays.asList(validatorRules));
    }

    public HandleErrorRule(List<ValidatorRule> validatorRules) {
        this.validatorRules = validatorRules;
    }

    @Override
    public void validate(X509Certificate certificate) throws CertificateValidationException {
        for (ValidatorRule validatorRule : validatorRules) {
            try {
                validatorRule.validate(certificate);
            } catch (FailedValidationException e) {
                throw e;
            } catch (CertificateValidationException e) {
                // No action.
            }
        }
    }
}
