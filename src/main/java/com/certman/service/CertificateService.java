package com.certman.service;

import com.certman.config.CertManProperties;
import com.certman.domain.*;
import com.certman.engine.*;
import com.certman.repository.CertificateAuthorityRepository;
import com.certman.repository.CertificateRepository;
import com.certman.repository.CertificateRequestRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service for certificate lifecycle management: create, sign, revoke, renew, export.
 */
@Service
@Transactional
public class CertificateService {

    private static final Logger log = LoggerFactory.getLogger(CertificateService.class);

    private final CertificateRepository certificateRepository;
    private final CertificateAuthorityRepository caRepository;
    private final CertificateRequestRepository csrRepository;
    private final KeyPairGenerator keyPairGenerator;
    private final CertificateBuilder certificateBuilder;
    private final CertificateExporter certificateExporter;
    private final PemUtils pemUtils;
    private final SerialNumberGenerator serialNumberGenerator;
    private final CertManProperties properties;
    private final AuditService auditService;

    public CertificateService(
            CertificateRepository certificateRepository,
            CertificateAuthorityRepository caRepository,
            CertificateRequestRepository csrRepository,
            KeyPairGenerator keyPairGenerator,
            CertificateBuilder certificateBuilder,
            CertificateExporter certificateExporter,
            PemUtils pemUtils,
            SerialNumberGenerator serialNumberGenerator,
            CertManProperties properties,
            AuditService auditService) {
        this.certificateRepository = certificateRepository;
        this.caRepository = caRepository;
        this.csrRepository = csrRepository;
        this.keyPairGenerator = keyPairGenerator;
        this.certificateBuilder = certificateBuilder;
        this.certificateExporter = certificateExporter;
        this.pemUtils = pemUtils;
        this.serialNumberGenerator = serialNumberGenerator;
        this.properties = properties;
        this.auditService = auditService;
    }

    /**
     * Issue a new end-entity certificate signed by the specified CA.
     */
    public Certificate issueCertificate(
            UUID issuingCaId,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            String subjectAltNames,
            CertificateType certificateType,
            KeyAlgorithm keyAlgorithm,
            int validityDays) {

        log.info("Issuing {} certificate for CN={} from CA {}", certificateType, commonName, issuingCaId);

        CertificateAuthority ca = caRepository.findById(issuingCaId)
                .orElseThrow(() -> new IllegalArgumentException("Issuing CA not found: " + issuingCaId));

        if (!ca.isActive()) {
            throw new IllegalStateException("Issuing CA '" + ca.getName() + "' is not active");
        }

        // Generate key pair for the new certificate
        KeyPair subjectKeyPair = keyPairGenerator.generateKeyPair(keyAlgorithm);

        // Build subject DN
        X500Name subject = certificateBuilder.buildSubjectDn(
                commonName, organizationalUnit, organization, locality, state, country);

        // Reconstruct CA key pair
        KeyPair issuerKeyPair = pemUtils.reconstructKeyPair(ca.getPrivateKeyPem(), ca.getCertificatePem());
        X500Name issuerDn = certificateBuilder.buildSubjectDn(
                ca.getCommonName(), ca.getOrganizationalUnit(),
                ca.getOrganization(), ca.getLocality(),
                ca.getState(), ca.getCountry());

        BigInteger serialNumber = serialNumberGenerator.nextSerialNumber();
        String sigAlg = ca.getSignatureAlgorithm();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(validityDays > 0 ? validityDays : properties.getDefaults().getValidityDays());

        // Don't outlive the CA
        if (notAfter.isAfter(ca.getNotAfter())) {
            notAfter = ca.getNotAfter();
        }

        // Parse SANs
        String[] sans = parseSans(subjectAltNames);

        // Generate certificate
        X509Certificate x509Cert = certificateBuilder.generateEndEntityCertificate(
                subject, subjectKeyPair.getPublic(), issuerDn, issuerKeyPair,
                sigAlg, serialNumber, notBefore, notAfter,
                certificateType, sans, ca.getCrlDistributionPoint());

        // Build key usage strings for storage
        String keyUsageStr = getKeyUsageString(certificateType);
        String extKeyUsageStr = getExtKeyUsageString(certificateType);

        // Persist
        Certificate cert = new Certificate();
        cert.setCommonName(commonName);
        cert.setOrganization(organization);
        cert.setOrganizationalUnit(organizationalUnit);
        cert.setLocality(locality);
        cert.setState(state);
        cert.setCountry(country);
        cert.setSubjectAlternativeNames(subjectAltNames);
        cert.setCertificateType(certificateType);
        cert.setKeyAlgorithm(keyAlgorithm);
        cert.setSignatureAlgorithm(sigAlg);
        cert.setCertificatePem(pemUtils.certificateToPem(x509Cert));
        cert.setPrivateKeyPem(pemUtils.privateKeyToPem(subjectKeyPair.getPrivate()));
        cert.setSerialNumber(serialNumber.toString(16).toUpperCase());
        cert.setThumbprintSha256(pemUtils.calculateThumbprint(x509Cert));
        cert.setNotBefore(notBefore);
        cert.setNotAfter(notAfter);
        cert.setStatus(CertificateStatus.ACTIVE);
        cert.setIssuingCa(ca);
        cert.setKeyUsage(keyUsageStr);
        cert.setExtendedKeyUsage(extKeyUsageStr);

        cert = certificateRepository.save(cert);

        auditService.logAction("ISSUE_CERTIFICATE", "Certificate",
                cert.getId().toString(),
                "Issued " + certificateType.getDisplayName() + " certificate for CN=" + commonName +
                        " signed by CA '" + ca.getName() + "'");

        return cert;
    }

    /**
     * Revoke a certificate with the specified reason.
     */
    public Certificate revokeCertificate(UUID certificateId, RevocationReason reason) {
        Certificate cert = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + certificateId));

        if (cert.isRevoked()) {
            throw new IllegalStateException("Certificate is already revoked");
        }

        cert.setStatus(CertificateStatus.REVOKED);
        cert.setRevocationReason(reason);
        cert.setRevokedAt(LocalDateTime.now());

        cert = certificateRepository.save(cert);

        auditService.logAction("REVOKE_CERTIFICATE", "Certificate",
                cert.getId().toString(),
                "Revoked certificate CN=" + cert.getCommonName() +
                        " (Serial: " + cert.getSerialNumber() + ") Reason: " + reason.getDisplayName());

        return cert;
    }

    /**
     * Renew a certificate by issuing a new one with the same parameters.
     */
    public Certificate renewCertificate(UUID certificateId, int validityDays) {
        Certificate original = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + certificateId));

        // Revoke the old certificate
        if (original.getStatus() == CertificateStatus.ACTIVE) {
            revokeCertificate(certificateId, RevocationReason.SUPERSEDED);
        }

        // Issue a new certificate with the same parameters
        Certificate renewed = issueCertificate(
                original.getIssuingCa().getId(),
                original.getCommonName(),
                original.getOrganization(),
                original.getOrganizationalUnit(),
                original.getLocality(),
                original.getState(),
                original.getCountry(),
                original.getSubjectAlternativeNames(),
                original.getCertificateType(),
                original.getKeyAlgorithm(),
                validityDays);

        auditService.logAction("RENEW_CERTIFICATE", "Certificate",
                renewed.getId().toString(),
                "Renewed certificate CN=" + renewed.getCommonName() +
                        " (replaces Serial: " + original.getSerialNumber() + ")");

        return renewed;
    }

    /**
     * Sign an external CSR (CertificateRequest entity) and issue a certificate.
     */
    public Certificate signCertificateRequest(UUID requestId, UUID issuingCaId, int validityDays) {
        CertificateRequest request = csrRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("CSR not found: " + requestId));

        if (request.getRequestStatus() != RequestStatus.PENDING) {
            throw new IllegalStateException("CSR is not in PENDING status");
        }

        CertificateAuthority ca = caRepository.findById(issuingCaId)
                .orElseThrow(() -> new IllegalArgumentException("Issuing CA not found: " + issuingCaId));

        if (!ca.isActive()) {
            throw new IllegalStateException("Issuing CA is not active");
        }

        // Parse the CSR PEM
        PKCS10CertificationRequest csr = pemUtils.parseCsr(request.getCsrPem());

        // Reconstruct CA key pair
        KeyPair issuerKeyPair = pemUtils.reconstructKeyPair(ca.getPrivateKeyPem(), ca.getCertificatePem());
        X500Name issuerDn = certificateBuilder.buildSubjectDn(
                ca.getCommonName(), ca.getOrganizationalUnit(),
                ca.getOrganization(), ca.getLocality(),
                ca.getState(), ca.getCountry());

        BigInteger serialNumber = serialNumberGenerator.nextSerialNumber();
        String sigAlg = ca.getSignatureAlgorithm();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(
                validityDays > 0 ? validityDays : request.getRequestedValidityDays());
        if (notAfter.isAfter(ca.getNotAfter())) {
            notAfter = ca.getNotAfter();
        }

        String[] sans = parseSans(request.getSubjectAlternativeNames());

        X509Certificate x509Cert = certificateBuilder.signCsr(
                csr, issuerDn, issuerKeyPair, sigAlg, serialNumber,
                notBefore, notAfter, request.getRequestedType(), sans,
                ca.getCrlDistributionPoint());

        // Persist issued certificate (no private key since CSR was external)
        Certificate cert = new Certificate();
        cert.setCommonName(request.getCommonName());
        cert.setOrganization(request.getOrganization());
        cert.setOrganizationalUnit(request.getOrganizationalUnit());
        cert.setLocality(request.getLocality());
        cert.setState(request.getState());
        cert.setCountry(request.getCountry());
        cert.setSubjectAlternativeNames(request.getSubjectAlternativeNames());
        cert.setCertificateType(request.getRequestedType());
        cert.setKeyAlgorithm(KeyAlgorithm.RSA_4096); // from CSR, we don't know exact
        cert.setSignatureAlgorithm(sigAlg);
        cert.setCertificatePem(pemUtils.certificateToPem(x509Cert));
        cert.setPrivateKeyPem("EXTERNAL_CSR_NO_PRIVATE_KEY");
        cert.setCsrPem(request.getCsrPem());
        cert.setSerialNumber(serialNumber.toString(16).toUpperCase());
        cert.setThumbprintSha256(pemUtils.calculateThumbprint(x509Cert));
        cert.setNotBefore(notBefore);
        cert.setNotAfter(notAfter);
        cert.setStatus(CertificateStatus.ACTIVE);
        cert.setIssuingCa(ca);
        cert.setKeyUsage(getKeyUsageString(request.getRequestedType()));
        cert.setExtendedKeyUsage(getExtKeyUsageString(request.getRequestedType()));

        cert = certificateRepository.save(cert);

        // Update the request
        request.setRequestStatus(RequestStatus.APPROVED);
        request.setIssuedCertificate(cert);
        request.setTargetCa(ca);
        request.setProcessedAt(LocalDateTime.now());
        csrRepository.save(request);

        auditService.logAction("SIGN_CSR", "Certificate",
                cert.getId().toString(),
                "Signed CSR for CN=" + request.getCommonName() +
                        " using CA '" + ca.getName() + "'");

        return cert;
    }

    /**
     * Reject a certificate request.
     */
    public CertificateRequest rejectCertificateRequest(UUID requestId, String reason) {
        CertificateRequest request = csrRepository.findById(requestId)
                .orElseThrow(() -> new IllegalArgumentException("CSR not found: " + requestId));

        request.setRequestStatus(RequestStatus.REJECTED);
        request.setRejectionReason(reason);
        request.setProcessedAt(LocalDateTime.now());

        request = csrRepository.save(request);

        auditService.logAction("REJECT_CSR", "CertificateRequest",
                request.getId().toString(),
                "Rejected CSR for CN=" + request.getCommonName() + " Reason: " + reason);

        return request;
    }

    /**
     * Submit an external CSR for signing.
     */
    public CertificateRequest submitCsr(
            String csrPem,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            String subjectAltNames,
            CertificateType requestedType,
            int validityDays,
            String requesterName,
            String requesterEmail,
            String notes) {

        // Validate CSR PEM
        pemUtils.parseCsr(csrPem);

        CertificateRequest request = new CertificateRequest();
        request.setCommonName(commonName);
        request.setOrganization(organization);
        request.setOrganizationalUnit(organizationalUnit);
        request.setLocality(locality);
        request.setState(state);
        request.setCountry(country);
        request.setSubjectAlternativeNames(subjectAltNames);
        request.setRequestedType(requestedType);
        request.setCsrPem(csrPem);
        request.setRequestStatus(RequestStatus.PENDING);
        request.setRequestedValidityDays(validityDays);
        request.setRequesterName(requesterName);
        request.setRequesterEmail(requesterEmail);
        request.setNotes(notes);

        request = csrRepository.save(request);

        auditService.logAction("SUBMIT_CSR", "CertificateRequest",
                request.getId().toString(),
                "CSR submitted for CN=" + commonName + " by " + requesterName);

        return request;
    }

    // --- Export Methods ---

    public byte[] exportAsPkcs12(UUID certificateId, String password) {
        Certificate cert = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        if ("EXTERNAL_CSR_NO_PRIVATE_KEY".equals(cert.getPrivateKeyPem())) {
            throw new IllegalStateException("Cannot export PKCS#12 for externally-submitted CSR certificates (no private key)");
        }

        X509Certificate x509Cert = pemUtils.parseCertificate(cert.getCertificatePem());
        java.security.PrivateKey privateKey = pemUtils.parsePrivateKey(cert.getPrivateKeyPem());

        // Build chain: cert + CA cert
        X509Certificate caCert = pemUtils.parseCertificate(cert.getIssuingCa().getCertificatePem());

        return certificateExporter.exportPkcs12(
                x509Cert, privateKey, new X509Certificate[]{caCert},
                cert.getCommonName(), password);
    }

    public String exportCertificateChainPem(UUID certificateId) {
        Certificate cert = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        X509Certificate x509Cert = pemUtils.parseCertificate(cert.getCertificatePem());
        X509Certificate caCert = pemUtils.parseCertificate(cert.getIssuingCa().getCertificatePem());

        return certificateExporter.exportCertificateChainPem(x509Cert, caCert);
    }

    public byte[] exportCertificateDer(UUID certificateId) {
        Certificate cert = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        X509Certificate x509Cert = pemUtils.parseCertificate(cert.getCertificatePem());
        return certificateExporter.exportCertificateDer(x509Cert);
    }

    // --- Query Methods ---

    @Transactional(readOnly = true)
    public List<Certificate> getAllCertificates() {
        return certificateRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<Certificate> getCertificateById(UUID id) {
        return certificateRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<Certificate> getCertificatesByStatus(CertificateStatus status) {
        return certificateRepository.findByStatus(status);
    }

    @Transactional(readOnly = true)
    public List<Certificate> getExpiringCertificates(int withinDays) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime threshold = now.plusDays(withinDays);
        return certificateRepository.findExpiringCertificates(now, threshold);
    }

    @Transactional(readOnly = true)
    public List<Certificate> searchByCommonName(String query) {
        return certificateRepository.findByCommonNameContainingIgnoreCase(query);
    }

    @Transactional(readOnly = true)
    public long countByStatus(CertificateStatus status) {
        return certificateRepository.countByStatus(status);
    }

    @Transactional(readOnly = true)
    public List<CertificateRequest> getAllRequests() {
        return csrRepository.findAllOrderByCreatedAtDesc();
    }

    @Transactional(readOnly = true)
    public List<CertificateRequest> getPendingRequests() {
        return csrRepository.findByRequestStatusOrderByCreatedAtDesc(RequestStatus.PENDING);
    }

    @Transactional(readOnly = true)
    public Optional<CertificateRequest> getRequestById(UUID id) {
        return csrRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public long countPendingRequests() {
        return csrRepository.countByStatus(RequestStatus.PENDING);
    }

    // --- Scheduled Tasks ---

    /**
     * Automatically mark expired certificates.
     * Runs every hour.
     */
    @Scheduled(fixedRate = 3600000)
    public void markExpiredCertificates() {
        List<Certificate> expired = certificateRepository.findExpiredButActive();
        for (Certificate cert : expired) {
            cert.setStatus(CertificateStatus.EXPIRED);
            certificateRepository.save(cert);
            auditService.logAction("AUTO_EXPIRE", "Certificate",
                    cert.getId().toString(),
                    "Certificate CN=" + cert.getCommonName() + " automatically marked as expired");
        }
        if (!expired.isEmpty()) {
            log.info("Marked {} certificates as expired", expired.size());
        }
    }

    // --- Private Helpers ---

    private String[] parseSans(String subjectAltNames) {
        if (subjectAltNames == null || subjectAltNames.isBlank()) {
            return new String[0];
        }
        return subjectAltNames.split(",");
    }

    private String getKeyUsageString(CertificateType type) {
        return switch (type) {
            case SERVER -> "digitalSignature, keyEncipherment";
            case CLIENT -> "digitalSignature";
            case CODE_SIGNING -> "digitalSignature";
            case EMAIL -> "digitalSignature, keyEncipherment";
            default -> "digitalSignature, keyEncipherment";
        };
    }

    private String getExtKeyUsageString(CertificateType type) {
        return switch (type) {
            case SERVER -> "serverAuth";
            case CLIENT -> "clientAuth";
            case CODE_SIGNING -> "codeSigning";
            case EMAIL -> "emailProtection";
            default -> "serverAuth, clientAuth";
        };
    }
}