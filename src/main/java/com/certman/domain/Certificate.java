package com.certman.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents an X.509 certificate issued by a Certificate Authority.
 * Models the full certificate lifecycle per RFC 5280.
 */
@Entity
@Table(name = "certificates")
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String commonName;

    private String organization;
    private String organizationalUnit;
    private String locality;
    private String state;
    private String country;

    /** Comma-separated Subject Alternative Names (DNS, IP, Email) */
    @Column(length = 2048)
    private String subjectAlternativeNames;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType certificateType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private KeyAlgorithm keyAlgorithm;

    @Column(nullable = false)
    private String signatureAlgorithm;

    @Lob
    @Column(nullable = false, columnDefinition = "CLOB")
    private String certificatePem;

    @Lob
    @Column(nullable = false, columnDefinition = "CLOB")
    private String privateKeyPem;

    @Lob
    @Column(columnDefinition = "CLOB")
    private String csrPem;

    @Column(nullable = false, unique = true)
    private String serialNumber;

    @Column(nullable = false)
    private String thumbprintSha256;

    @Column(nullable = false)
    private LocalDateTime notBefore;

    @Column(nullable = false)
    private LocalDateTime notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateStatus status = CertificateStatus.ACTIVE;

    @Enumerated(EnumType.STRING)
    private RevocationReason revocationReason;

    private LocalDateTime revokedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuing_ca_id", nullable = false)
    private CertificateAuthority issuingCa;

    /** Key Usage flags (comma-separated): digitalSignature, keyEncipherment, etc. */
    @Column(length = 512)
    private String keyUsage;

    /** Extended Key Usage OIDs (comma-separated): serverAuth, clientAuth, etc. */
    @Column(length = 512)
    private String extendedKeyUsage;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // --- Helper Methods ---

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(notAfter);
    }

    public boolean isActive() {
        return status == CertificateStatus.ACTIVE && !isExpired();
    }

    public boolean isRevoked() {
        return status == CertificateStatus.REVOKED;
    }

    public long getDaysUntilExpiry() {
        return java.time.Duration.between(LocalDateTime.now(), notAfter).toDays();
    }

    public String getSubjectDn() {
        StringBuilder sb = new StringBuilder();
        if (commonName != null) sb.append("CN=").append(commonName);
        if (organizationalUnit != null) sb.append(", OU=").append(organizationalUnit);
        if (organization != null) sb.append(", O=").append(organization);
        if (locality != null) sb.append(", L=").append(locality);
        if (state != null) sb.append(", ST=").append(state);
        if (country != null) sb.append(", C=").append(country);
        return sb.toString();
    }

    // --- Getters and Setters ---

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getCommonName() { return commonName; }
    public void setCommonName(String commonName) { this.commonName = commonName; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getOrganizationalUnit() { return organizationalUnit; }
    public void setOrganizationalUnit(String organizationalUnit) { this.organizationalUnit = organizationalUnit; }

    public String getLocality() { return locality; }
    public void setLocality(String locality) { this.locality = locality; }

    public String getState() { return state; }
    public void setState(String state) { this.state = state; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public String getSubjectAlternativeNames() { return subjectAlternativeNames; }
    public void setSubjectAlternativeNames(String subjectAlternativeNames) { this.subjectAlternativeNames = subjectAlternativeNames; }

    public CertificateType getCertificateType() { return certificateType; }
    public void setCertificateType(CertificateType certificateType) { this.certificateType = certificateType; }

    public KeyAlgorithm getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(KeyAlgorithm keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }

    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }

    public String getCertificatePem() { return certificatePem; }
    public void setCertificatePem(String certificatePem) { this.certificatePem = certificatePem; }

    public String getPrivateKeyPem() { return privateKeyPem; }
    public void setPrivateKeyPem(String privateKeyPem) { this.privateKeyPem = privateKeyPem; }

    public String getCsrPem() { return csrPem; }
    public void setCsrPem(String csrPem) { this.csrPem = csrPem; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public String getThumbprintSha256() { return thumbprintSha256; }
    public void setThumbprintSha256(String thumbprintSha256) { this.thumbprintSha256 = thumbprintSha256; }

    public LocalDateTime getNotBefore() { return notBefore; }
    public void setNotBefore(LocalDateTime notBefore) { this.notBefore = notBefore; }

    public LocalDateTime getNotAfter() { return notAfter; }
    public void setNotAfter(LocalDateTime notAfter) { this.notAfter = notAfter; }

    public CertificateStatus getStatus() { return status; }
    public void setStatus(CertificateStatus status) { this.status = status; }

    public RevocationReason getRevocationReason() { return revocationReason; }
    public void setRevocationReason(RevocationReason revocationReason) { this.revocationReason = revocationReason; }

    public LocalDateTime getRevokedAt() { return revokedAt; }
    public void setRevokedAt(LocalDateTime revokedAt) { this.revokedAt = revokedAt; }

    public CertificateAuthority getIssuingCa() { return issuingCa; }
    public void setIssuingCa(CertificateAuthority issuingCa) { this.issuingCa = issuingCa; }

    public String getKeyUsage() { return keyUsage; }
    public void setKeyUsage(String keyUsage) { this.keyUsage = keyUsage; }

    public String getExtendedKeyUsage() { return extendedKeyUsage; }
    public void setExtendedKeyUsage(String extendedKeyUsage) { this.extendedKeyUsage = extendedKeyUsage; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}