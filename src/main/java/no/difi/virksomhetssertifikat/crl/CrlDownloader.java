package no.difi.virksomhetssertifikat.crl;


import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;

import java.io.*;
import java.net.URL;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;


/**
 * LAster ned crler til disk.
 *
 * Det blir kun skrevet til disk hvis vi kan 1) laste ned og 2) verifisere at crllisten er korrekt.
 *
 * Det blir også lagret en fil med navn timestamp, som innholder siste tidspunkt for siste vellykkede nedlasting. Timestampet
 * blir oppdatert hvis _en_ av crlene kan lastes ned og validers.
 */
public class CrlDownloader {
    private static final Log LOG = LogFactory.getLog(CrlDownloader.class.getName());

    private String crlDownloadPath;


    public CrlDownloader(String crlDownloadPath) {
        this.crlDownloadPath = crlDownloadPath;
    }

    public List<File> downloadValidateAndSave(HashSet<String> urls) throws CRLException, IOException, CertificateException {
        boolean fileWriten = false;
        CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
        ArrayList<File> files = new ArrayList<File>(urls.size());
        for(String url: urls){

            InputStream inputStream = new URL(url).openStream();
            byte[] bytes = IOUtils.toByteArray(inputStream);
            ByteArrayInputStream byteInputStream = new ByteArrayInputStream(bytes);
            try{
            Collection<? extends CRL> crls = certificatefactory.generateCRLs(byteInputStream);
            if (crls.isEmpty()) {
                LOG.warn("The crl url " + url + " responded with a crl containing no (zero) crl definitions");
            } else {
                byteInputStream.reset();

                File crl = new File(crlDownloadPath, urlToFilename(url));
                crl.createNewFile();
                FileOutputStream randomFile = new FileOutputStream(crl);
                try{
                    IOUtils.copy(byteInputStream, randomFile);
                }finally {
                    IOUtils.closeQuietly(randomFile);
                }
                files.add(crl);

                fileWriten = true;
            }
            }finally {
                IOUtils.closeQuietly(inputStream);
                IOUtils.closeQuietly(byteInputStream);
            }
        }

        if(fileWriten){
            updateTimestamp();
        }

        return files;
    }

    private void updateTimestamp() throws IOException {
        File crl = new File(crlDownloadPath, "timestamp");
        crl.createNewFile();
        FileUtils.writeStringToFile(crl, Long.toString(DateTime.now().getMillis()));
    }

    public String urlToFilename(String url) {
        return url.replace(":", "").replace("/", "-");
    }
}
