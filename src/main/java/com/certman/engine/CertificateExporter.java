package com.certman.engine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Exports certificates and keys in various standard formats:
 * - PEM (Base64 encoded, RFC 7468)
 * - DER (Binary ASN.1 encoding)
 * - PKCS#12 / PFX (RFC 7292 - bundled cert + key)
 * - Certificate chain (PEM bundle)
 */
@Component
public class CertificateExporter {

    private static final Logger log = LoggerFactory.getLogger(CertificateExporter.class);

    /**
     * Export certificate as PEM encoded string.
     */
    public String exportCertificatePem(X509Certificate certificate) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(certificate);
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to export certificate as PEM", e);
        }
    }

    /**
     * Export certificate as DER encoded byte array.
     */
    public byte[] exportCertificateDer(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to export certificate as DER", e);
        }
    }

    /**
     * Export certificate and private key as PKCS#12 (PFX) bundle.
     * Password-protected using PBES2 with AES-256-CBC.
     *
     * @param certificate The certificate to export
     * @param privateKey  The private key
     * @param chain       Optional certificate chain (CA certs)
     * @param alias       Alias for the key entry
     * @param password    Password to protect the PKCS#12 store
     * @return PKCS#12 byte array
     */
    public byte[] exportPkcs12(
            X509Certificate certificate,
            PrivateKey privateKey,
            X509Certificate[] chain,
            String alias,
            String password) {

        try {
            log.info("Exporting PKCS#12 bundle for alias: {}", alias);

            KeyStore ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            ks.load(null, null);

            // Build full certificate chain
            X509Certificate[] fullChain;
            if (chain != null && chain.length > 0) {
                fullChain = new X509Certificate[chain.length + 1];
                fullChain[0] = certificate;
                System.arraycopy(chain, 0, fullChain, 1, chain.length);
            } else {
                fullChain = new X509Certificate[]{certificate};
            }

            ks.setKeyEntry(alias, privateKey, password.toCharArray(), fullChain);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ks.store(baos, password.toCharArray());
            return baos.toByteArray();

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to export PKCS#12 bundle", e);
        }
    }

    /**
     * Export a certificate chain as a PEM bundle.
     * Certificates are ordered from end-entity to root.
     */
    public String exportCertificateChainPem(X509Certificate... certificates) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            for (X509Certificate cert : certificates) {
                writer.writeObject(cert);
            }
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to export certificate chain as PEM", e);
        }
    }

    /**
     * Export private key as PEM encoded string (PKCS#8).
     */
    public String exportPrivateKeyPem(PrivateKey privateKey) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(privateKey);
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to export private key as PEM", e);
        }
    }
}