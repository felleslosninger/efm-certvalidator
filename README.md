

#Virksomhetsvalidator

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

##Organisasjonsnummer

I henhold til http://www.regjeringen.no/upload/FAD/Vedlegg/IKT-politikk/SEID_Leveranse_1_-_v1.02.pdf side 24 så henter
vi ut orgnummer fra subject feltet. Dette orgnummeret kan stoles på hvis alle andre valideringer er gjennomført og
i orden.

##Chain validatorer

Alle virksomhetssertifikater må utstedes av en godkjent part. Denne parten må tilgjengelig gjøre to sertifikater, ett
rotsertifikat og ett mellomliggende sertifikat. Virksomhetssertifikatet må utstedes fra det mellomliggende sertifikatet. Med
utstedes mener vi signert av.

Vi bruker java sin implementasjon av cert path builder, som sikrer at vi har en komplett kjede fra sertifikatet og helt
opp til rot.

Vi krever også at virksomhetssertifikatet inneholder en policy som utsteder offentliggjør og som vi, ved hjelp av konfig
godkjenner. Sertifikater som har feil eller ikke godkjente policyer er ikke gyldige.

I tillegg til disse validatorene har vi validatorer for utgåtte sertifikater, for håndtering av kritiske extensions og
revokering av sertifikatet via OSCP og CRL.


##Distribusjon

Difi ønsker ikke på nåværende tidspunkt å fi gi hele kildekoden, men kan dele prosjektet med andre godkjente prosjekter.
Kildekoden er lagt i et privat repo på github og publisert binært i difis artifactory / maven repo. Binære og kildekode
skal ikke distribueres utover dette.

##Installasjon


Krever java 7, pga CRLReason som er ute av java 8.

På mac kan dette gjøres slik:

        JAVA_HOME=`/usr/libexec/java_home  -v 1.7` mvn test


### Maven avhenighet.


        <dependency>
            <groupId>no.difi</groupId>
            <artifactId>Virksomhetssertifikatvalidator</artifactId>
            <version>1.1-SNAPSHOT</version>
        </dependency>