package no.difi.virksomhetssertifikat.usage;

import no.difi.virksomhetssertifikat.ExpirationValidator;
import no.difi.virksomhetssertifikat.ValidatorBuilder;
import no.difi.virksomhetssertifikat.api.PrincipalNameProvider;
import no.difi.virksomhetssertifikat.extras.NorwegianOrganizationNumberValidator;
import org.junit.Test;

public class Virksomhetssertifikat {

    @Test
    public void simple() {
        ValidatorBuilder.newInstance()
                .append(new ExpirationValidator())
                .append(new NorwegianOrganizationNumberValidator(new PrincipalNameProvider() {
                    @Override
                    public boolean validate(String value) {
                        return true;
                    }
                }))
                .build();
    }
}