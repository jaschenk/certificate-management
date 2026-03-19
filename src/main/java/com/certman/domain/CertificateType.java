package com.certman.domain;

/**
 * Types of X.509 certificates managed by the system.
 */
public enum CertificateType {
    ROOT_CA("Root CA", "Self-signed root Certificate Authority"),
    INTERMEDIATE_CA("Intermediate CA", "Intermediate Certificate Authority signed by a Root CA"),
    SERVER("Server/TLS", "Server authentication certificate (TLS/SSL)"),
    CLIENT("Client", "Client authentication certificate"),
    CODE_SIGNING("Code Signing", "Certificate for code signing operations"),
    EMAIL("Email/S-MIME", "Certificate for email encryption and signing");

    private final String displayName;
    private final String description;

    CertificateType(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() { return displayName; }
    public String getDescription() { return description; }
}