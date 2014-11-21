package no.difi.virksomhetssertifikat;


public class VirksomhetsValidationException  extends Exception{
    public VirksomhetsValidationException(String reason, Throwable cause){
        super(reason, cause);
    }
}
