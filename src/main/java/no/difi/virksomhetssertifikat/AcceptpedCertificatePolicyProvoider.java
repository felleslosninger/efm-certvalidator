package no.difi.virksomhetssertifikat;

import java.util.Arrays;
import java.util.List;

public class AcceptpedCertificatePolicyProvoider {
    private List<String> list;

    public AcceptpedCertificatePolicyProvoider(String... args) {
        list = Arrays.asList(args);
    }

    public List<String> getApproprovedPolicyOids(){
        return list;
    }
}
