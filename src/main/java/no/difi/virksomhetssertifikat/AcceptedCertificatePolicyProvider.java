package no.difi.virksomhetssertifikat;

import java.util.Arrays;
import java.util.List;

public class AcceptedCertificatePolicyProvider {
    private List<String> list;

    public AcceptedCertificatePolicyProvider(String... args) {
        list = Arrays.asList(args);
    }

    public List<String> getApproprovedPolicyOids(){
        return list;
    }
}
