package com.certman.domain;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents a PKCS#10 Certificate Signing Request (CSR) per RFC 2986.
 * Tracks external CSR submissions through the approval workflow.
 */
@Entity
@Table(name = "certificate_requests")
public class CertificateRequest {

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

    /** Comma-separated Subject Alternative Names */
    @Column(length = 2048)
    private String subjectAlternativeNames;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType requestedType;

    @Lob
    @Column(nullable = false, columnDefinition = "CLOB")
    private String csrPem;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequestStatus requestStatus = RequestStatus.PENDING;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "target_ca_id")
    private CertificateAuthority targetCa;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issued_certificate_id")
    private Certificate issuedCertificate;

    private int requestedValidityDays = 365;

    private String requesterName;
    private String requesterEmail;
    private String notes;
    private String rejectionReason;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
    private LocalDateTime processedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
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
    public void setSubjectAlternativeNames(String san) { this.subjectAlternativeNames = san; }

    public CertificateType getRequestedType() { return requestedType; }
    public void setRequestedType(CertificateType requestedType) { this.requestedType = requestedType; }

    public String getCsrPem() { return csrPem; }
    public void setCsrPem(String csrPem) { this.csrPem = csrPem; }

    public RequestStatus getRequestStatus() { return requestStatus; }
    public void setRequestStatus(RequestStatus requestStatus) { this.requestStatus = requestStatus; }

    public CertificateAuthority getTargetCa() { return targetCa; }
    public void setTargetCa(CertificateAuthority targetCa) { this.targetCa = targetCa; }

    public Certificate getIssuedCertificate() { return issuedCertificate; }
    public void setIssuedCertificate(Certificate issuedCertificate) { this.issuedCertificate = issuedCertificate; }

    public int getRequestedValidityDays() { return requestedValidityDays; }
    public void setRequestedValidityDays(int requestedValidityDays) { this.requestedValidityDays = requestedValidityDays; }

    public String getRequesterName() { return requesterName; }
    public void setRequesterName(String requesterName) { this.requesterName = requesterName; }

    public String getRequesterEmail() { return requesterEmail; }
    public void setRequesterEmail(String requesterEmail) { this.requesterEmail = requesterEmail; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    public String getRejectionReason() { return rejectionReason; }
    public void setRejectionReason(String rejectionReason) { this.rejectionReason = rejectionReason; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }

    public LocalDateTime getProcessedAt() { return processedAt; }
    public void setProcessedAt(LocalDateTime processedAt) { this.processedAt = processedAt; }

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
}