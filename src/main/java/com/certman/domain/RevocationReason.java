package com.certman.domain;

/**
 * Certificate revocation reasons per RFC 5280 Section 5.3.1.
 */
public enum RevocationReason {
    UNSPECIFIED(0, "Unspecified"),
    KEY_COMPROMISE(1, "Key Compromise"),
    CA_COMPROMISE(2, "CA Compromise"),
    AFFILIATION_CHANGED(3, "Affiliation Changed"),
    SUPERSEDED(4, "Superseded"),
    CESSATION_OF_OPERATION(5, "Cessation of Operation"),
    CERTIFICATE_HOLD(6, "Certificate Hold"),
    REMOVE_FROM_CRL(8, "Remove from CRL"),
    PRIVILEGE_WITHDRAWN(9, "Privilege Withdrawn"),
    AA_COMPROMISE(10, "AA Compromise");

    private final int code;
    private final String displayName;

    RevocationReason(int code, String displayName) {
        this.code = code;
        this.displayName = displayName;
    }

    public int getCode() { return code; }
    public String getDisplayName() { return displayName; }

    public static RevocationReason fromCode(int code) {
        for (RevocationReason reason : values()) {
            if (reason.code == code) return reason;
        }
        return UNSPECIFIED;
    }
}