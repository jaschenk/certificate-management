package com.certman.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents a Certificate Authority (CA) in the PKI hierarchy.
 * Supports both Root CAs (self-signed) and Intermediate CAs (signed by parent).
 * Conforms to RFC 5280 Section 4.2.1.9 (Basic Constraints).
 */
@Entity
@Table(name = "certificate_authorities")
public class CertificateAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private String commonName;

    private String organization;
    private String organizationalUnit;
    private String locality;
    private String state;
    private String country;

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

    @Column(nullable = false, unique = true)
    private String serialNumber;

    @Column(nullable = false)
    private LocalDateTime notBefore;

    @Column(nullable = false)
    private LocalDateTime notAfter;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateStatus status = CertificateStatus.ACTIVE;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_ca_id")
    private CertificateAuthority parentCa;

    @OneToMany(mappedBy = "parentCa", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<CertificateAuthority> childCas = new ArrayList<>();

    @OneToMany(mappedBy = "issuingCa", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Certificate> issuedCertificates = new ArrayList<>();

    @Column(nullable = false)
    private int pathLengthConstraint = -1; // -1 means no constraint

    @Column(nullable = false)
    private long nextSerialNumber = 2L;

    private String crlDistributionPoint;

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

    public boolean isRootCa() {
        return parentCa == null;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(notAfter);
    }

    public boolean isActive() {
        return status == CertificateStatus.ACTIVE && !isExpired();
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

    public synchronized long getAndIncrementSerialNumber() {
        return nextSerialNumber++;
    }

    // --- Getters and Setters ---

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

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

    public KeyAlgorithm getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(KeyAlgorithm keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }

    public String getSignatureAlgorithm() { return signatureAlgorithm; }
    public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }

    public String getCertificatePem() { return certificatePem; }
    public void setCertificatePem(String certificatePem) { this.certificatePem = certificatePem; }

    public String getPrivateKeyPem() { return privateKeyPem; }
    public void setPrivateKeyPem(String privateKeyPem) { this.privateKeyPem = privateKeyPem; }

    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }

    public LocalDateTime getNotBefore() { return notBefore; }
    public void setNotBefore(LocalDateTime notBefore) { this.notBefore = notBefore; }

    public LocalDateTime getNotAfter() { return notAfter; }
    public void setNotAfter(LocalDateTime notAfter) { this.notAfter = notAfter; }

    public CertificateStatus getStatus() { return status; }
    public void setStatus(CertificateStatus status) { this.status = status; }

    public CertificateAuthority getParentCa() { return parentCa; }
    public void setParentCa(CertificateAuthority parentCa) { this.parentCa = parentCa; }

    public List<CertificateAuthority> getChildCas() { return childCas; }
    public void setChildCas(List<CertificateAuthority> childCas) { this.childCas = childCas; }

    public List<Certificate> getIssuedCertificates() { return issuedCertificates; }
    public void setIssuedCertificates(List<Certificate> issuedCertificates) { this.issuedCertificates = issuedCertificates; }

    public int getPathLengthConstraint() { return pathLengthConstraint; }
    public void setPathLengthConstraint(int pathLengthConstraint) { this.pathLengthConstraint = pathLengthConstraint; }

    public long getNextSerialNumber() { return nextSerialNumber; }
    public void setNextSerialNumber(long nextSerialNumber) { this.nextSerialNumber = nextSerialNumber; }

    public String getCrlDistributionPoint() { return crlDistributionPoint; }
    public void setCrlDistributionPoint(String crlDistributionPoint) { this.crlDistributionPoint = crlDistributionPoint; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
}