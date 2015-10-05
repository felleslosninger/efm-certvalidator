package no.difi.virksomhetssertifikat.api;

public interface PrincipalNameProvider {
    boolean validate(String value);
}
