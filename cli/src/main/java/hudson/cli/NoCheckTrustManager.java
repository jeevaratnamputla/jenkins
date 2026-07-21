package hudson.cli;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.util.logging.Logger;

/**
 * A trust manager that delegates certificate validation to the JVM's default
 * trust chain (via {@link TrustManagerFactory}), using the platform's default
 * {@link KeyStore}.
 *
 * <p>This replaces the previous no-op implementation that accepted every
 * certificate unconditionally, which was vulnerable to man-in-the-middle
 * attacks. Callers that previously relied on certificate-check bypass
 * (e.g. the {@code -noCertificateCheck} CLI flag) should avoid installing
 * a custom {@link javax.net.ssl.SSLContext} altogether and let the JVM
 * default validation apply.
 *
 * @author Kohsuke Kawaguchi
 */
public class NoCheckTrustManager implements X509TrustManager {

    private static final Logger LOGGER = Logger.getLogger(NoCheckTrustManager.class.getName());

    /** The real trust manager obtained from the JVM default trust store. */
    private final X509TrustManager delegate;

    /**
     * Creates a {@code NoCheckTrustManager} backed by the JVM default trust store.
     *
     * @throws RuntimeException if the default {@link TrustManagerFactory} cannot
     *         be initialised (wraps {@link NoSuchAlgorithmException} or
     *         {@link KeyStoreException}).
     */
    public NoCheckTrustManager() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // Passing null uses the default JVM KeyStore (cacerts).
            tmf.init((KeyStore) null);
            X509TrustManager found = null;
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    found = (X509TrustManager) tm;
                    break;
                }
            }
            if (found == null) {
                throw new IllegalStateException("No X509TrustManager found in default TrustManagerFactory");
            }
            this.delegate = found;
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException("Failed to initialise default TrustManagerFactory", e);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
        delegate.checkClientTrusted(x509Certificates, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
        delegate.checkServerTrusted(x509Certificates, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
