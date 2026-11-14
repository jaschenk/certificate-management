package com.certman.service;

import com.certman.config.CertManProperties;
import com.certman.domain.*;
import com.certman.engine.CertificateBuilder;
import com.certman.engine.KeyPairGenerator;
import com.certman.engine.PemUtils;
import com.certman.engine.SerialNumberGenerator;
import com.certman.repository.CertificateAuthorityRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * Service for managing Certificate Authorities (Root and Intermediate).
 * Handles CA creation, key generation, and lifecycle management.
 */
@Service
@Transactional
public class CertificateAuthorityService {

    private static final Logger log = LoggerFactory.getLogger(CertificateAuthorityService.class);

    private final CertificateAuthorityRepository caRepository;
    private final KeyPairGenerator keyPairGenerator;
    private final CertificateBuilder certificateBuilder;
    private final PemUtils pemUtils;
    private final SerialNumberGenerator serialNumberGenerator;
    private final CertManProperties properties;
    private final AuditService auditService;

    public CertificateAuthorityService(
            CertificateAuthorityRepository caRepository,
            KeyPairGenerator keyPairGenerator,
            CertificateBuilder certificateBuilder,
            PemUtils pemUtils,
            SerialNumberGenerator serialNumberGenerator,
            CertManProperties properties,
            AuditService auditService) {
        this.caRepository = caRepository;
        this.keyPairGenerator = keyPairGenerator;
        this.certificateBuilder = certificateBuilder;
        this.pemUtils = pemUtils;
        this.serialNumberGenerator = serialNumberGenerator;
        this.properties = properties;
        this.auditService = auditService;
    }

    /**
     * Create a new self-signed Root Certificate Authority.
     */
    public CertificateAuthority createRootCa(
            String name,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            KeyAlgorithm keyAlgorithm,
            int validityDays,
            int pathLengthConstraint) {

        log.info("Creating Root CA: {}", name);

        if (caRepository.existsByName(name)) {
            throw new IllegalArgumentException("CA with name '" + name + "' already exists");
        }

        // Generate key pair
        KeyPair keyPair = keyPairGenerator.generateKeyPair(keyAlgorithm);

        // Build subject DN
        X500Name subject = certificateBuilder.buildSubjectDn(
                commonName, organizationalUnit, organization, locality, state, country);

        // Determine signature algorithm
        String sigAlg = keyAlgorithm.getDefaultSignatureAlgorithm();

        // Serial number
        BigInteger serialNumber = serialNumberGenerator.nextSerialNumber();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(validityDays > 0 ? validityDays : properties.getDefaults().getCaValidityDays());

        // Generate self-signed certificate
        X509Certificate cert = certificateBuilder.generateRootCaCertificate(
                subject, keyPair, sigAlg, serialNumber, notBefore, notAfter,
                pathLengthConstraint, properties.getCrl().getDistributionPoint());

        // Persist CA entity
        CertificateAuthority ca = new CertificateAuthority();
        ca.setName(name);
        ca.setCommonName(commonName);
        ca.setOrganization(organization);
        ca.setOrganizationalUnit(organizationalUnit);
        ca.setLocality(locality);
        ca.setState(state);
        ca.setCountry(country);
        ca.setKeyAlgorithm(keyAlgorithm);
        ca.setSignatureAlgorithm(sigAlg);
        ca.setCertificatePem(pemUtils.certificateToPem(cert));
        ca.setPrivateKeyPem(pemUtils.privateKeyToPem(keyPair.getPrivate()));
        ca.setSerialNumber(serialNumber.toString(16).toUpperCase());
        ca.setNotBefore(notBefore);
        ca.setNotAfter(notAfter);
        ca.setStatus(CertificateStatus.ACTIVE);
        ca.setPathLengthConstraint(pathLengthConstraint);
        ca.setCrlDistributionPoint(properties.getCrl().getDistributionPoint());
        ca.setNextSerialNumber(2L);

        ca = caRepository.save(ca);

        auditService.logAction("CREATE_ROOT_CA", "CertificateAuthority",
                ca.getId().toString(),
                "Created Root CA '" + name + "' with " + keyAlgorithm.getDisplayName());

        log.info("Root CA '{}' created successfully with ID: {}", name, ca.getId());
        return ca;
    }

    /**
     * Create an Intermediate CA signed by a parent CA.
     */
    public CertificateAuthority createIntermediateCa(
            String name,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            KeyAlgorithm keyAlgorithm,
            int validityDays,
            int pathLengthConstraint,
            UUID parentCaId) {

        log.info("Creating Intermediate CA: {} under parent CA: {}", name, parentCaId);

        if (caRepository.existsByName(name)) {
            throw new IllegalArgumentException("CA with name '" + name + "' already exists");
        }

        CertificateAuthority parentCa = caRepository.findById(parentCaId)
                .orElseThrow(() -> new IllegalArgumentException("Parent CA not found: " + parentCaId));

        if (!parentCa.isActive()) {
            throw new IllegalStateException("Parent CA is not active");
        }

        // Generate key pair for intermediate CA
        KeyPair subjectKeyPair = keyPairGenerator.generateKeyPair(keyAlgorithm);

        // Build subject DN
        X500Name subject = certificateBuilder.buildSubjectDn(
                commonName, organizationalUnit, organization, locality, state, country);

        // Reconstruct parent CA key pair
        KeyPair issuerKeyPair = pemUtils.reconstructKeyPair(
                parentCa.getPrivateKeyPem(), parentCa.getCertificatePem());
        X500Name issuerDn = certificateBuilder.buildSubjectDn(
                parentCa.getCommonName(), parentCa.getOrganizationalUnit(),
                parentCa.getOrganization(), parentCa.getLocality(),
                parentCa.getState(), parentCa.getCountry());

        String sigAlg = parentCa.getSignatureAlgorithm();
        BigInteger serialNumber = serialNumberGenerator.nextSerialNumber();

        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(validityDays > 0 ? validityDays : properties.getDefaults().getCaValidityDays());

        // Ensure intermediate CA doesn't outlive parent
        if (notAfter.isAfter(parentCa.getNotAfter())) {
            notAfter = parentCa.getNotAfter();
        }

        X509Certificate cert = certificateBuilder.generateIntermediateCaCertificate(
                subject, subjectKeyPair.getPublic(), issuerDn, issuerKeyPair,
                sigAlg, serialNumber, notBefore, notAfter,
                pathLengthConstraint, properties.getCrl().getDistributionPoint());

        CertificateAuthority ca = new CertificateAuthority();
        ca.setName(name);
        ca.setCommonName(commonName);
        ca.setOrganization(organization);
        ca.setOrganizationalUnit(organizationalUnit);
        ca.setLocality(locality);
        ca.setState(state);
        ca.setCountry(country);
        ca.setKeyAlgorithm(keyAlgorithm);
        ca.setSignatureAlgorithm(keyAlgorithm.getDefaultSignatureAlgorithm());
        ca.setCertificatePem(pemUtils.certificateToPem(cert));
        ca.setPrivateKeyPem(pemUtils.privateKeyToPem(subjectKeyPair.getPrivate()));
        ca.setSerialNumber(serialNumber.toString(16).toUpperCase());
        ca.setNotBefore(notBefore);
        ca.setNotAfter(notAfter);
        ca.setStatus(CertificateStatus.ACTIVE);
        ca.setParentCa(parentCa);
        ca.setPathLengthConstraint(pathLengthConstraint);
        ca.setCrlDistributionPoint(properties.getCrl().getDistributionPoint());
        ca.setNextSerialNumber(2L);

        ca = caRepository.save(ca);

        auditService.logAction("CREATE_INTERMEDIATE_CA", "CertificateAuthority",
                ca.getId().toString(),
                "Created Intermediate CA '" + name + "' signed by '" + parentCa.getName() + "'");

        log.info("Intermediate CA '{}' created successfully with ID: {}", name, ca.getId());
        return ca;
    }

    // --- Query Methods ---

    @Transactional(readOnly = true)
    public List<CertificateAuthority> getAllCas() {
        return caRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<CertificateAuthority> getActiveCas() {
        return caRepository.findActiveCas();
    }

    @Transactional(readOnly = true)
    public List<CertificateAuthority> getRootCas() {
        return caRepository.findRootCas();
    }

    @Transactional(readOnly = true)
    public List<CertificateAuthority> getIntermediateCas() {
        return caRepository.findIntermediateCas();
    }

    @Transactional(readOnly = true)
    public Optional<CertificateAuthority> getCaById(UUID id) {
        return caRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Optional<CertificateAuthority> getCaByName(String name) {
        return caRepository.findByName(name);
    }

    @Transactional(readOnly = true)
    public long countByStatus(CertificateStatus status) {
        return caRepository.countByStatus(status);
    }
}