package no.difi.virksomhetssertifikat.usage;

import no.difi.virksomhetssertifikat.rule.CRLRule;
import no.difi.virksomhetssertifikat.rule.ExpirationRule;
import no.difi.virksomhetssertifikat.ValidatorBuilder;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import no.difi.virksomhetssertifikat.extra.NorwegianOrganizationNumberRule;
import org.testng.annotations.Test;

public class VirksomhetssertifikatTest {

    @Test
    public void simple() {
        ValidatorBuilder.newInstance()
                .addRule(new ExpirationRule())
                .addRule(new NorwegianOrganizationNumberRule(new PrincipalNameProvider() {
                    @Override
                    public boolean validate(String value) {
                        return true;
                    }
                }))
                .addRule(new CRLRule())
                .build();
    }
}
