package no.difi.virksomhetssertifikat.orgnr;


public interface TrustedOrgNummerProvider {
    boolean isTrusted(String orgNumber);
}
