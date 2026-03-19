package com.certman.domain;

/**
 * Certificate lifecycle status per RFC 5280 Section 3.3.
 */
public enum CertificateStatus {
    ACTIVE("Active", "Certificate is valid and in use"),
    EXPIRED("Expired", "Certificate has passed its validity period"),
    REVOKED("Revoked", "Certificate has been revoked by the CA"),
    PENDING("Pending", "Certificate request is awaiting approval"),
    SUSPENDED("Suspended", "Certificate is temporarily suspended");

    private final String displayName;
    private final String description;

    CertificateStatus(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
}