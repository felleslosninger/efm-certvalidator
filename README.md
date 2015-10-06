# Certificate validator for X.509 certificates

This validator is not a single validator, it is set of building blocks to build the certificate validator (using X.509 certificates) fitting the needs of your business case.

A lot of sensible defaults is used to make it easy to get started using this library. Use a proper IDE to customize to your needs.


## Getting started

Include dependency in your pom.xml:

```xml
<dependency>
    <groupId>no.difi.commons</groupId>
    <artifactId>commons-certvalidator</artifactId>
    <version>1.2.0</version>
</dependency>
```

Create your own validator(s):

```java
// Generic validator
ValidatorHelper validator = ValidatorBuilder.newInstace()
    .append(new ExpirationValidator())
    .append(new SelfsignedValidator())
    .append(new CRLValidator())
    .append(new OCSPValidator())
    .build();

// Accept only non-expired selfsigned certificates
ValidatorHelper validator = ValidatorBuilder.newInstace()
    .append(new ExpirationValidator())
    .append(new SelfsignedValidator(SelfsignedValidator.Kind.SELF_SIGNED_ONLY))
    .build();

// Is the certificate expiring in less than 7 days?
ValidatorHelper validator = ValidatorBuilder.newInstace()
    .append(new ExpirationSoonValidator(7 * 24 * 60 * 60 * 1000))
    .build();
    
// Validate your certificate (throws exception on error)
validator.validate(...);

// Validate your certificate (returns boolean)
validator.isValid(...);
```

Please note the ValidatorHelper accepts ```InputStream```, ```byte[]``` and ```X509Certificate``` as input for validation.

Validators may not only be used to judge a given certificate when in situation to trust or not to trust a certificate. A validator instance may be used to implement logic helping users to handle certificates in a better manner (ie. give a warning before certificate expires). 


## Available building blocks

* **ChainValidator** - Validates chain of trust of certificate given access to root certificates and intermediate certificates.
* **CriticalOidValidator**
* **CRLValidator** - Use information regarding Certificate Revocation List (CRL) in certificate to validate certificate.
* **DummyValidator** - Very simple implementation potentially interesting to use in testing.
* **ExpirationSoonValidator**
* **ExpirationValidator**
* **JunctionValidator** - Combine multiple validators into one validator using ```AND```, ```OR``` and ```XOR```.
* **OCSPValidator**
* **PrincipalNameValidator**
* **SelfsignedValidator**
* **SuiteValidator** *(extends JunctionValidator)* - Special instance of ```JunctionValidator``` with ```AND```. This is used by ValidatorHelper to combine multiple validators.


### Extras

* **NorwegianOrganizationNumberValidator** *(extends PrincipalNameValidator)* - Implements logic to fetch a norwegian organization number from a certificate given [standardization](http://www.regjeringen.no/upload/FAD/Vedlegg/IKT-politikk/SEID_Leveranse_1_-_v1.02.pdf) is used.


## Exceptions

* **CertificateValidatorException** - This is thrown if anything around validation of certificate results in problems.
* **FailedValidationException** *(extends CertificateValidatorException)* - This is thrown when certificate is validated to not be valid.
* **CertificateBucketException** *(extends CertificateValidatorException)* - This is thrown when there are problems regarding certificate buckets.


## Creating new building blocks

All new validation rules must implement the very simple ```CertificateValidator``` interface to be included in a chain of validators. Even ```ValidatorHelper``` implements this interface to allow combination of validators.


# Old stuff

## Virksomhetsvalidator

Formålet med dette biblioteket er å kunne bruke PKI og Virksomhetssertifkater til autentisering av klienter. Dette gjøres
via asymmetriske nøkler og signeringer og kan gjøres uten større konfigurasjon av klientens tilgang i forkant.  For å
godkjenne klienter ved kun bruk av den offentlige nøkkelen og signering vi man kunne sikre seg at klienten besitter den
private nøkkelen. Besittelse av den private nøkkelen vil i PKI- og virksomhetssertifikat-sammenheng være en garanti for
at avsender er den den utgir seg for å være.

For å være sikker på at avsender har privatnøkkelen må man sjekke at

  * sertifikatet er korrekt, gyldig og utstedt av noen man stoler på.
  * At meldingen man mottar er signert av privatnøkklen(kontrollert med den offentlige nøkkelen)

Hvis begge punktene er i orden vil man kunne stole på innholdet i sertifikatet og klienten. Hvis en av punktene eller
deler av punktene ikke holder åpner man for angrep.

Referanser:

  * PKI http://en.wikipedia.org/wiki/Public_key_infrastructure
  * https://www.regjeringen.no/nb/dokumenter/kravspesifikasjon-for-pki-i-offentlig-se/id611085/


Dette biblioteket er tenkt som en felles plass for validering av virkshomhetssertifikater. Biblioteket inneholder en
del forskjellige validatorer som i kombinasjon kan validere et innkommende sertifikat opp mot retningslinjer og
standarder. Både i PKI og i norsk forstand.

## Organisasjonsnummer

I henhold til http://www.regjeringen.no/upload/FAD/Vedlegg/IKT-politikk/SEID_Leveranse_1_-_v1.02.pdf side 24 så henter
vi ut orgnummer fra subject feltet. Dette orgnummeret kan stoles på hvis alle andre valideringer er gjennomført og
i orden.

## Chain validatorer

Alle virksomhetssertifikater må utstedes av en godkjent part. Denne parten må tilgjengelig gjøre to sertifikater, ett
rotsertifikat og ett mellomliggende sertifikat. Virksomhetssertifikatet må utstedes fra det mellomliggende sertifikatet. Med
utstedes mener vi signert av.

Vi bruker java sin implementasjon av cert path builder, som sikrer at vi har en komplett kjede fra sertifikatet og helt
opp til rot.

Vi krever også at virksomhetssertifikatet inneholder en policy som utsteder offentliggjør og som vi, ved hjelp av konfig
godkjenner. Sertifikater som har feil eller ikke godkjente policyer er ikke gyldige.

I tillegg til disse validatorene har vi validatorer for utgåtte sertifikater, for håndtering av kritiske extensions og
revokering av sertifikatet via OSCP og CRL.
