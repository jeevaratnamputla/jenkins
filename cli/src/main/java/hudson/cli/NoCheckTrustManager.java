package hudson.cli;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A trust manager that delegates certificate validation to the JVM's default
 * {@link TrustManagerFactory}, backed by the system {@link KeyStore}.
 *
 * <p>This replaces the former no-op implementation that accepted every
 * certificate unconditionally (vulnerable to man-in-the-middle attacks).
 * Certificate validation is now performed properly using the platform's
 * trusted CA store.
 *
 * @author Kohsuke Kawaguchi
 */
public class NoCheckTrustManager implements X509TrustManager {

    private final X509TrustManager delegate;

    /**
     * Creates a {@code NoCheckTrustManager} backed by the JVM default trust store.
     *
     * @throws RuntimeException if the default {@link TrustManagerFactory} cannot be initialised
     */
    public NoCheckTrustManager() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null); // null → uses the JVM default trust store
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
            throw new IllegalStateException("Failed to initialise default TrustManagerFactory", e);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
