package no.difi.certvalidator.lang;

import no.difi.certvalidator.api.CertificateValidationException;

public class ValidatorParsingException extends CertificateValidationException {

    public ValidatorParsingException(String message) {
        super(message);
    }

    public ValidatorParsingException(String reason, Throwable cause) {
        super(reason, cause);
    }
}
