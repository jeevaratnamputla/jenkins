package hudson.cli;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;
import java.util.logging.Logger;

/**
 * A trust manager that bypasses certificate validation when the user has
 * explicitly opted in via the {@code -noCertificateCheck} flag.
 *
 * <p><strong>WARNING:</strong> Skipping certificate verification exposes the
 * connection to man-in-the-middle attacks. This must only be instantiated
 * when {@code noCertificateCheck} is {@code true}, i.e. the user has
 * deliberately acknowledged the risk.
 *
 * @author Kohsuke Kawaguchi
 */
public class NoCheckTrustManager implements X509TrustManager {

    private static final Logger LOGGER = Logger.getLogger(NoCheckTrustManager.class.getName());

    /**
     * Creates a {@code NoCheckTrustManager}.
     *
     * @param noCertificateCheck must be {@code true}; if {@code false} a
     *        {@link IllegalStateException} is thrown to prevent accidental
     *        use of this unsafe trust manager.
     */
    public NoCheckTrustManager(boolean noCertificateCheck) {
        if (!noCertificateCheck) {
            throw new IllegalStateException(
                    "NoCheckTrustManager must only be used when certificate checking is explicitly disabled by the user.");
        }
        LOGGER.warning("TLS certificate verification is disabled. This connection is vulnerable to man-in-the-middle attacks.");
    }

    @Override
    @SuppressFBWarnings(value = "WEAK_TRUST_MANAGER", justification = "User explicitly set -noCertificateCheck to skip verification.")
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        // Certificate validation intentionally skipped per explicit user opt-in (-noCertificateCheck).
    }

    @Override
    @SuppressFBWarnings(value = "WEAK_TRUST_MANAGER", justification = "User explicitly set -noCertificateCheck to skip verification.")
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        // Certificate validation intentionally skipped per explicit user opt-in (-noCertificateCheck).
    }

    @Override
    @SuppressFBWarnings(value = "WEAK_TRUST_MANAGER", justification = "User explicitly set -noCertificateCheck to skip verification.")
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
