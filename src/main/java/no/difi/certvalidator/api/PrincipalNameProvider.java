package no.difi.certvalidator.api;

/**
 * Used by PrincipalNameValidator to implement validation logic.
 */
public interface PrincipalNameProvider {
    boolean validate(String value);
}
