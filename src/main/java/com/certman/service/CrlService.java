package com.certman.service;

import com.certman.domain.Certificate;
import com.certman.domain.CertificateAuthority;
import com.certman.engine.CrlGenerator;
import com.certman.engine.PemUtils;
import com.certman.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for generating and caching Certificate Revocation Lists.
 */
@Service
@Transactional(readOnly = true)
public class CrlService {

    private static final Logger log = LoggerFactory.getLogger(CrlService.class);

    private final CertificateRepository certificateRepository;
    private final CrlGenerator crlGenerator;
    private final PemUtils pemUtils;

    // CRL number counter per CA
    private final ConcurrentHashMap<String, AtomicLong> crlNumbers = new ConcurrentHashMap<>();
    // CRL cache per CA
    private final ConcurrentHashMap<String, CachedCrl> crlCache = new ConcurrentHashMap<>();

    public CrlService(
            CertificateRepository certificateRepository,
            CrlGenerator crlGenerator,
            PemUtils pemUtils) {
        this.certificateRepository = certificateRepository;
        this.crlGenerator = crlGenerator;
        this.pemUtils = pemUtils;
    }

    /**
     * Generate or return cached CRL for the specified CA.
     */
    public X509CRL getCrl(CertificateAuthority ca) {
        String caId = ca.getId().toString();

        CachedCrl cached = crlCache.get(caId);
        if (cached != null && !cached.isExpired()) {
            return cached.crl();
        }

        return generateCrl(ca);
    }

    /**
     * Force regeneration of the CRL for the specified CA.
     */
    public X509CRL generateCrl(CertificateAuthority ca) {
        String caId = ca.getId().toString();
        log.info("Generating CRL for CA: {}", ca.getName());

        // Get all revoked certificates for this CA
        List<Certificate> revokedCerts = certificateRepository.findRevokedByCA(ca);

        List<CrlGenerator.RevokedCertEntry> entries = revokedCerts.stream()
                .map(cert -> new CrlGenerator.RevokedCertEntry(
                        new BigInteger(cert.getSerialNumber(), 16),
                        Date.from(cert.getRevokedAt().atZone(ZoneId.systemDefault()).toInstant()),
                        cert.getRevocationReason() != null ? cert.getRevocationReason().getCode() : 0
                ))
                .toList();

        // Build CA details
        X500Name issuerDn = new X500Name(ca.getSubjectDn());
        KeyPair issuerKeyPair = pemUtils.reconstructKeyPair(ca.getPrivateKeyPem(), ca.getCertificatePem());

        long crlNum = crlNumbers.computeIfAbsent(caId, k -> new AtomicLong(1)).getAndIncrement();
        LocalDateTime thisUpdate = LocalDateTime.now();
        LocalDateTime nextUpdate = thisUpdate.plusHours(24);

        X509CRL crl = crlGenerator.generateCrl(
                issuerDn, issuerKeyPair, ca.getSignatureAlgorithm(),
                BigInteger.valueOf(crlNum), thisUpdate, nextUpdate, entries);

        crlCache.put(caId, new CachedCrl(crl, nextUpdate));

        log.info("CRL generated for CA '{}' with {} entries, CRL#{}", ca.getName(), entries.size(), crlNum);
        return crl;
    }

    /**
     * Get CRL as DER-encoded bytes for download.
     */
    public byte[] getCrlDer(CertificateAuthority ca) {
        try {
            X509CRL crl = getCrl(ca);
            return crl.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode CRL as DER", e);
        }
    }

    private record CachedCrl(X509CRL crl, LocalDateTime expiresAt) {
        boolean isExpired() {
            return LocalDateTime.now().isAfter(expiresAt);
        }
    }
}