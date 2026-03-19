package com.certman.engine;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

/**
 * Generates X.509 Certificate Revocation Lists (CRLs) per RFC 5280 Section 5.
 * Supports CRL v2 format with CRL Number and Reason Code extensions.
 */
@Component
public class CrlGenerator {

    private static final Logger log = LoggerFactory.getLogger(CrlGenerator.class);

    /**
     * Represents an entry in the CRL.
     */
    public record RevokedCertEntry(
            BigInteger serialNumber,
            Date revocationDate,
            int reasonCode
    ) {}

    /**
     * Generate a CRL signed by the given CA.
     *
     * @param issuerDn           CA distinguished name
     * @param issuerKeyPair      CA key pair for signing
     * @param signatureAlgorithm Signature algorithm to use
     * @param crlNumber          CRL sequence number
     * @param thisUpdate         CRL issue date
     * @param nextUpdate         Next expected CRL update
     * @param revokedEntries     List of revoked certificate entries
     * @return Signed X509CRL object
     */
    public X509CRL generateCrl(
            X500Name issuerDn,
            KeyPair issuerKeyPair,
            String signatureAlgorithm,
            BigInteger crlNumber,
            LocalDateTime thisUpdate,
            LocalDateTime nextUpdate,
            List<RevokedCertEntry> revokedEntries) {

        try {
            log.info("Generating CRL #{} with {} revoked entries for: {}",
                    crlNumber, revokedEntries.size(), issuerDn);

            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                    issuerDn,
                    toDate(thisUpdate)
            );
            crlBuilder.setNextUpdate(toDate(nextUpdate));

            // Add CRL Number extension (RFC 5280 Section 5.2.3)
            crlBuilder.addExtension(Extension.cRLNumber, false,
                    new CRLNumber(crlNumber));

            // Add revoked certificate entries with reason code
            for (RevokedCertEntry entry : revokedEntries) {
                crlBuilder.addCRLEntry(
                        entry.serialNumber(),
                        entry.revocationDate(),
                        entry.reasonCode()
                );
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(issuerKeyPair.getPrivate());

            X509CRLHolder crlHolder = crlBuilder.build(signer);

            // Convert to java.security.cert.X509CRL
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509CRL) cf.generateCRL(
                    new java.io.ByteArrayInputStream(crlHolder.getEncoded()));

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to generate CRL", e);
        }
    }

    private Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}