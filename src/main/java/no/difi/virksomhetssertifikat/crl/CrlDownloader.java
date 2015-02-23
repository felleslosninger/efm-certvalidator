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
        ArrayList<File> files = new ArrayList<File>(urls.size());
        for(String url: urls){
            File file;

            file = downloadValidateCrl(url);
            if(file != null){
                files.add(file);
                fileWriten = true;
            }
        }

        if(fileWriten){
            updateTimestamp();
        }

        return files;
    }

    public File downloadValidateCrl(String url) throws CertificateException, IOException, CRLException{
        InputStream inputStream = null;
        ByteArrayInputStream byteInputStream = null;
        try{
            LOG.info("Downloading CRL url "+ url);
            CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
            inputStream = new URL(url).openStream();
            byte[] bytes = IOUtils.toByteArray(inputStream);
            byteInputStream = new ByteArrayInputStream(bytes);
            Collection<? extends CRL> crls = certificatefactory.generateCRLs(byteInputStream);
            if (crls.isEmpty()) {
                LOG.warn("The CRL url " + url + " responded with a crl containing no (zero) CRL definitions");
            } else {
                byteInputStream.reset();

                File crl = new File(crlDownloadPath, FileCrlLoader.urlToFilename(url));
                crl.createNewFile();
                File urlFile = new File(crlDownloadPath, FileCrlLoader.urlToFilename(url) + ".url");
                urlFile.createNewFile();
                FileOutputStream file = new FileOutputStream(crl);
                FileOutputStream urlFileStream = new FileOutputStream(urlFile);

                try{
                    IOUtils.write(url, urlFileStream);
                    IOUtils.copy(byteInputStream, file);
                }finally {
                    IOUtils.closeQuietly(file);
                    IOUtils.closeQuietly(urlFileStream);
                }
                return crl;
            }
        } catch (Exception e) {
            LOG.error("Failed to download and save CRL " + url, e);
        } finally {
            IOUtils.closeQuietly(inputStream);
            IOUtils.closeQuietly(byteInputStream);
        }
        return null;
    }

    private void updateTimestamp() throws IOException {
        File crl = new File(crlDownloadPath, "timestamp");
        crl.createNewFile();
        FileUtils.writeStringToFile(crl, Long.toString(DateTime.now().getMillis()));
    }


}
