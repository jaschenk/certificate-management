package com.certman.engine;

import com.certman.domain.CertificateType;
import com.certman.domain.KeyAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

/**
 * Core certificate builder implementing X.509v3 certificate generation per RFC 5280.
 *
 * Supports:
 * - Self-signed Root CA certificates with Basic Constraints
 * - Intermediate CA certificates with path length constraints
 * - End-entity certificates (Server, Client, Code Signing, Email)
 * - CSR generation and signing (PKCS#10 / RFC 2986)
 * - Key Usage and Extended Key Usage extensions
 * - Subject Alternative Names (SAN)
 * - Authority/Subject Key Identifiers
 * - CRL Distribution Points
 */
@Component
public class CertificateBuilder {

    private static final Logger log = LoggerFactory.getLogger(CertificateBuilder.class);

    /**
     * Build an X.500 Distinguished Name from individual components.
     */
    public X500Name buildSubjectDn(String cn, String ou, String o, String l, String st, String c) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (c != null && !c.isBlank()) builder.addRDN(BCStyle.C, c);
        if (st != null && !st.isBlank()) builder.addRDN(BCStyle.ST, st);
        if (l != null && !l.isBlank()) builder.addRDN(BCStyle.L, l);
        if (o != null && !o.isBlank()) builder.addRDN(BCStyle.O, o);
        if (ou != null && !ou.isBlank()) builder.addRDN(BCStyle.OU, ou);
        if (cn != null && !cn.isBlank()) builder.addRDN(BCStyle.CN, cn);
        return builder.build();
    }

    /**
     * Generate a self-signed Root CA certificate.
     * Sets BasicConstraints(cA=TRUE), Key Usage for cert/CRL signing,
     * and Subject/Authority Key Identifiers per RFC 5280.
     */
    public X509Certificate generateRootCaCertificate(
            X500Name subject,
            KeyPair keyPair,
            String signatureAlgorithm,
            BigInteger serialNumber,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            int pathLengthConstraint,
            String crlDistributionPoint) {

        try {
            log.info("Generating Root CA certificate for: {}", subject);

            Date startDate = toDate(notBefore);
            Date endDate = toDate(notAfter);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    subject,           // issuer = subject (self-signed)
                    serialNumber,
                    startDate,
                    endDate,
                    subject,
                    keyPair.getPublic()
            );

            // Basic Constraints: CA=true (RFC 5280 Section 4.2.1.9)
            if (pathLengthConstraint >= 0) {
                certBuilder.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(pathLengthConstraint));
            } else {
                certBuilder.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(true));
            }

            // Key Usage: keyCertSign, cRLSign (RFC 5280 Section 4.2.1.3)
            certBuilder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            // Subject Key Identifier (RFC 5280 Section 4.2.1.2)
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(calculateKeyId(spki)));

            // Authority Key Identifier (self-referencing for root)
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(calculateKeyId(spki)));

            // CRL Distribution Point
            if (crlDistributionPoint != null && !crlDistributionPoint.isBlank()) {
                addCrlDistributionPoint(certBuilder, crlDistributionPoint);
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());

            X509CertificateHolder holder = certBuilder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to generate Root CA certificate", e);
        }
    }

    /**
     * Generate an Intermediate CA certificate signed by a parent CA.
     */
    public X509Certificate generateIntermediateCaCertificate(
            X500Name subject,
            PublicKey subjectPublicKey,
            X500Name issuer,
            KeyPair issuerKeyPair,
            String signatureAlgorithm,
            BigInteger serialNumber,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            int pathLengthConstraint,
            String crlDistributionPoint) {

        try {
            log.info("Generating Intermediate CA certificate for: {}", subject);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    toDate(notBefore),
                    toDate(notAfter),
                    subject,
                    subjectPublicKey
            );

            // Basic Constraints: CA=true with path length
            if (pathLengthConstraint >= 0) {
                certBuilder.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(pathLengthConstraint));
            } else {
                certBuilder.addExtension(Extension.basicConstraints, true,
                        new BasicConstraints(true));
            }

            // Key Usage for CA
            certBuilder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            // Subject Key Identifier
            SubjectPublicKeyInfo subjectSpki = SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(calculateKeyId(subjectSpki)));

            // Authority Key Identifier (from issuer)
            SubjectPublicKeyInfo issuerSpki = SubjectPublicKeyInfo.getInstance(issuerKeyPair.getPublic().getEncoded());
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(calculateKeyId(issuerSpki)));

            // CRL Distribution Point
            if (crlDistributionPoint != null && !crlDistributionPoint.isBlank()) {
                addCrlDistributionPoint(certBuilder, crlDistributionPoint);
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(issuerKeyPair.getPrivate());

            X509CertificateHolder holder = certBuilder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to generate Intermediate CA certificate", e);
        }
    }

    /**
     * Generate an end-entity certificate (Server, Client, Code Signing, Email).
     * Signs with the issuing CA's key pair.
     */
    public X509Certificate generateEndEntityCertificate(
            X500Name subject,
            PublicKey subjectPublicKey,
            X500Name issuer,
            KeyPair issuerKeyPair,
            String signatureAlgorithm,
            BigInteger serialNumber,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            CertificateType certType,
            String[] subjectAltNames,
            String crlDistributionPoint) {

        try {
            log.info("Generating {} certificate for: {}", certType.getDisplayName(), subject);

            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    toDate(notBefore),
                    toDate(notAfter),
                    subject,
                    subjectPublicKey
            );

            // Basic Constraints: CA=false (end entity)
            certBuilder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(false));

            // Key Usage and Extended Key Usage based on cert type
            addKeyUsageForType(certBuilder, certType);
            addExtendedKeyUsageForType(certBuilder, certType);

            // Subject Key Identifier
            SubjectPublicKeyInfo subjectSpki = SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(calculateKeyId(subjectSpki)));

            // Authority Key Identifier
            SubjectPublicKeyInfo issuerSpki = SubjectPublicKeyInfo.getInstance(issuerKeyPair.getPublic().getEncoded());
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(calculateKeyId(issuerSpki)));

            // Subject Alternative Names (RFC 5280 Section 4.2.1.6)
            if (subjectAltNames != null && subjectAltNames.length > 0) {
                addSubjectAltNames(certBuilder, subjectAltNames);
            }

            // CRL Distribution Point
            if (crlDistributionPoint != null && !crlDistributionPoint.isBlank()) {
                addCrlDistributionPoint(certBuilder, crlDistributionPoint);
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(issuerKeyPair.getPrivate());

            X509CertificateHolder holder = certBuilder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to generate end-entity certificate", e);
        }
    }

    /**
     * Generate a PKCS#10 Certificate Signing Request (RFC 2986).
     */
    public PKCS10CertificationRequest generateCsr(
            X500Name subject,
            KeyPair keyPair,
            String signatureAlgorithm) {

        try {
            log.info("Generating CSR for: {}", subject);

            JcaPKCS10CertificationRequestBuilder csrBuilder =
                    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());

            return csrBuilder.build(signer);

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to generate CSR", e);
        }
    }

    /**
     * Sign a CSR and produce an end-entity certificate.
     */
    public X509Certificate signCsr(
            PKCS10CertificationRequest csr,
            X500Name issuer,
            KeyPair issuerKeyPair,
            String signatureAlgorithm,
            BigInteger serialNumber,
            LocalDateTime notBefore,
            LocalDateTime notAfter,
            CertificateType certType,
            String[] subjectAltNames,
            String crlDistributionPoint) {

        try {
            log.info("Signing CSR from: {}", csr.getSubject());

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    issuer,
                    serialNumber,
                    toDate(notBefore),
                    toDate(notAfter),
                    csr.getSubject(),
                    csr.getSubjectPublicKeyInfo()
            );

            // Basic Constraints: CA=false
            certBuilder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(false));

            // Key Usage and Extended Key Usage
            addKeyUsageForType(certBuilder, certType);
            addExtendedKeyUsageForType(certBuilder, certType);

            // Subject Key Identifier
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(calculateKeyId(csr.getSubjectPublicKeyInfo())));

            // Authority Key Identifier
            SubjectPublicKeyInfo issuerSpki = SubjectPublicKeyInfo.getInstance(issuerKeyPair.getPublic().getEncoded());
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(calculateKeyId(issuerSpki)));

            // Subject Alternative Names
            if (subjectAltNames != null && subjectAltNames.length > 0) {
                addSubjectAltNames(certBuilder, subjectAltNames);
            }

            // CRL Distribution Point
            if (crlDistributionPoint != null && !crlDistributionPoint.isBlank()) {
                addCrlDistributionPoint(certBuilder, crlDistributionPoint);
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(issuerKeyPair.getPrivate());

            X509CertificateHolder holder = certBuilder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);

        } catch (Exception e) {
            throw new CertificateEngineException("Failed to sign CSR", e);
        }
    }

    // --- Private Helper Methods ---

    private void addKeyUsageForType(X509v3CertificateBuilder builder, CertificateType type) throws Exception {
        int usage = switch (type) {
            case SERVER -> KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
            case CLIENT -> KeyUsage.digitalSignature;
            case CODE_SIGNING -> KeyUsage.digitalSignature;
            case EMAIL -> KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
            default -> KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        };
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
    }

    private void addExtendedKeyUsageForType(X509v3CertificateBuilder builder, CertificateType type) throws Exception {
        KeyPurposeId[] purposes = switch (type) {
            case SERVER -> new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth};
            case CLIENT -> new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth};
            case CODE_SIGNING -> new KeyPurposeId[]{KeyPurposeId.id_kp_codeSigning};
            case EMAIL -> new KeyPurposeId[]{KeyPurposeId.id_kp_emailProtection};
            default -> new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth};
        };
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(purposes));
    }

    private void addSubjectAltNames(X509v3CertificateBuilder builder, String[] sans) throws Exception {
        GeneralName[] names = new GeneralName[sans.length];
        for (int i = 0; i < sans.length; i++) {
            String san = sans[i].trim();
            if (san.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                // IPv4 address
                names[i] = new GeneralName(GeneralName.iPAddress, san);
            } else if (san.contains("@")) {
                // Email address
                names[i] = new GeneralName(GeneralName.rfc822Name, san);
            } else {
                // DNS name
                names[i] = new GeneralName(GeneralName.dNSName, san);
            }
        }
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(names));
    }

    private void addCrlDistributionPoint(X509v3CertificateBuilder builder, String url) throws Exception {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, url);
        DistributionPointName dpn = new DistributionPointName(new GeneralNames(gn));
        DistributionPoint dp = new DistributionPoint(dpn, null, null);
        builder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{dp}));
    }

    private byte[] calculateKeyId(SubjectPublicKeyInfo spki) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-1");
            return digest.digest(spki.getPublicKeyData().getBytes());
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to calculate key identifier", e);
        }
    }

    private Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    // Overloaded method for JcaX509v3CertificateBuilder
    private void addKeyUsageForType(JcaX509v3CertificateBuilder builder, CertificateType type) throws Exception {
        int usage = switch (type) {
            case SERVER -> KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
            case CLIENT -> KeyUsage.digitalSignature;
            case CODE_SIGNING -> KeyUsage.digitalSignature;
            case EMAIL -> KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
            default -> KeyUsage.digitalSignature | KeyUsage.keyEncipherment;
        };
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
    }

    private void addExtendedKeyUsageForType(JcaX509v3CertificateBuilder builder, CertificateType type) throws Exception {
        KeyPurposeId[] purposes = switch (type) {
            case SERVER -> new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth};
            case CLIENT -> new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth};
            case CODE_SIGNING -> new KeyPurposeId[]{KeyPurposeId.id_kp_codeSigning};
            case EMAIL -> new KeyPurposeId[]{KeyPurposeId.id_kp_emailProtection};
            default -> new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth};
        };
        builder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(purposes));
    }

    private void addSubjectAltNames(JcaX509v3CertificateBuilder builder, String[] sans) throws Exception {
        GeneralName[] names = new GeneralName[sans.length];
        for (int i = 0; i < sans.length; i++) {
            String san = sans[i].trim();
            if (san.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                names[i] = new GeneralName(GeneralName.iPAddress, san);
            } else if (san.contains("@")) {
                names[i] = new GeneralName(GeneralName.rfc822Name, san);
            } else {
                names[i] = new GeneralName(GeneralName.dNSName, san);
            }
        }
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(names));
    }

    private void addCrlDistributionPoint(JcaX509v3CertificateBuilder builder, String url) throws Exception {
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, url);
        DistributionPointName dpn = new DistributionPointName(new GeneralNames(gn));
        DistributionPoint dp = new DistributionPoint(dpn, null, null);
        builder.addExtension(Extension.cRLDistributionPoints, false,
                new CRLDistPoint(new DistributionPoint[]{dp}));
    }
}