package com.certman.engine;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Component;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Utility class for PEM encoding/decoding and certificate format conversions.
 * Handles PKCS#8 private keys, X.509 certificates, and PKCS#10 CSRs.
 */
@Component
public class PemUtils {

    private final JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);
    private final JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME);

    /**
     * Encode an object to PEM format string.
     */
    public String toPem(Object obj) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to encode object to PEM", e);
        }
    }

    /**
     * Encode a private key to PEM format using PKCS#8.
     */
    public String privateKeyToPem(PrivateKey privateKey) {
        return toPem(privateKey);
    }

    /**
     * Encode a certificate to PEM format.
     */
    public String certificateToPem(X509Certificate certificate) {
        return toPem(certificate);
    }

    /**
     * Parse a PEM-encoded private key.
     */
    public PrivateKey parsePrivateKey(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof PEMKeyPair pemKeyPair) {
                return keyConverter.getKeyPair(pemKeyPair).getPrivate();
            } else if (obj instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo pkInfo) {
                return keyConverter.getPrivateKey(pkInfo);
            }
            throw new CertificateEngineException("Unrecognized private key format");
        } catch (CertificateEngineException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to parse PEM private key", e);
        }
    }

    /**
     * Parse a PEM-encoded X.509 certificate.
     */
    public X509Certificate parseCertificate(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return certConverter.getCertificate(holder);
            }
            throw new CertificateEngineException("Unrecognized certificate format");
        } catch (CertificateEngineException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to parse PEM certificate", e);
        }
    }

    /**
     * Parse a PEM-encoded PKCS#10 CSR.
     */
    public PKCS10CertificationRequest parseCsr(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest csr) {
                return csr;
            }
            throw new CertificateEngineException("Unrecognized CSR format");
        } catch (CertificateEngineException e) {
            throw e;
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to parse PEM CSR", e);
        }
    }

    /**
     * Parse a PEM-encoded public key from a certificate.
     */
    public PublicKey parsePublicKeyFromCert(String certPem) {
        return parseCertificate(certPem).getPublicKey();
    }

    /**
     * Reconstruct a KeyPair from PEM-encoded private key and certificate.
     */
    public KeyPair reconstructKeyPair(String privateKeyPem, String certPem) {
        PrivateKey privateKey = parsePrivateKey(privateKeyPem);
        PublicKey publicKey = parsePublicKeyFromCert(certPem);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Calculate SHA-256 thumbprint of a certificate.
     */
    public String calculateThumbprint(X509Certificate certificate) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encoded = digest.digest(certificate.getEncoded());
            return Hex.toHexString(encoded).toUpperCase();
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to calculate certificate thumbprint", e);
        }
    }

    /**
     * Calculate SHA-256 thumbprint from PEM-encoded certificate.
     */
    public String calculateThumbprint(String certPem) {
        return calculateThumbprint(parseCertificate(certPem));
    }
}