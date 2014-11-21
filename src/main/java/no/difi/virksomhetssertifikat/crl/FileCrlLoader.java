package no.difi.virksomhetssertifikat.crl;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Laster crl filer fra disk og leverer en liste med objekter.
 */
public class FileCrlLoader {
    private String crlDirectory;

    public FileCrlLoader(String crlDirectory) {
        this.crlDirectory = crlDirectory;
    }

    public List<CRL> loadCachedCrls() throws CertificateException, CRLException, IOException {

        CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
        Collection<File> fileCrls = FileUtils.listFiles(new File(crlDirectory), null, true);

        ArrayList<CRL> crls = new ArrayList<CRL>();
        for(File fileCrl: fileCrls){
            InputStream inStream = FileUtils.openInputStream(fileCrl);
            Collection<? extends CRL> loaded;
            try{
                loaded = certificatefactory.generateCRLs(inStream);
            }finally {
                IOUtils.closeQuietly(inStream);
            }
            crls.addAll(loaded);
        }

        return crls;
    }
}
