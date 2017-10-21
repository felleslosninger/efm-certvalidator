package no.difi.certvalidator.api;

/**
 * @author erlend
 */
public interface ErrorHandler {

    void handle(CertificateValidationException e) throws FailedValidationException;

}
