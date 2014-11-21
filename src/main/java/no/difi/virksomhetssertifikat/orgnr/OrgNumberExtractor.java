package no.difi.virksomhetssertifikat.orgnr;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class OrgNumberExtractor {

    /**
     * Implementerer uthenting av orgnumber basert på http://www.regjeringen.no/upload/FAD/Vedlegg/IKT-politikk/SEID_Leveranse_1_-_v1.02.pdf side 24
     *
     *
     * @throws IllegalArgumentException hvis orgnummer ikke blir funnet
     * @param cert
     * @return
     */
    public String getOrgNumber(X509Certificate cert) {

        List<String> subjectParts = Arrays.asList(cert.getSubjectDN().getName().split(","));

        for(String part : subjectParts){
            part = part.trim();

            //matcher "C=NO,ST=AKERSHUS,L=FORNEBUVEIEN 1\\, 1366 LYSAKER,O=RF Commfides,SERIALNUMBER=399573952,CN=RF Commfides"
            if(part.startsWith("SERIALNUMBER=")){
                return part.split("=")[1];
            }

            //matcher "CN=name, OU=None, O=organisasjon - 123456789, L=None, C=None"
            String pattarn = "^O=.*\\-(.*)$";
            Matcher matcher = Pattern.compile(pattarn).matcher(part);
            if(matcher.matches()){
                return matcher.group(1).trim();
            }
        }


        throw new IllegalArgumentException("Certificate has no OrgNumber");
    }
}
