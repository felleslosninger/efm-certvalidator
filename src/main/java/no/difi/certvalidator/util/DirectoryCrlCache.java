package no.difi.certvalidator.util;

import no.difi.certvalidator.api.CertificateValidationException;
import no.difi.certvalidator.api.CrlCache;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;

/**
 * @author erlend
 */
public class DirectoryCrlCache implements CrlCache {

    private Path folder;

    public DirectoryCrlCache(Path folder) throws IOException {
        this.folder = folder;

        Files.createDirectories(folder);
    }

    @Override
    public X509CRL get(String url) throws CertificateValidationException {
        Path file = folder.resolve(filterUrl(url));

        if (!Files.exists(file))
            return null;

        try (InputStream inputStream = Files.newInputStream(file)) {
            return CrlUtils.load(inputStream);
        } catch (IOException | CRLException e) {
            return null;
        }
    }

    @Override
    public void set(String url, X509CRL crl) {
        Path file = folder.resolve(filterUrl(url));

        try (OutputStream outputStream = Files.newOutputStream(file)) {
            CrlUtils.save(outputStream, crl);
        } catch (IOException | CRLException e) {
            // No action.
        }
    }

    private String filterUrl(String s) {
        return s.replaceAll("[^a-zA-Z0-9.\\-]", "_");
    }
}
