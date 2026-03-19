package com.certman.domain;

/**
 * Status of a Certificate Signing Request in the approval workflow.
 */
public enum RequestStatus {
    PENDING("Pending Review"),
    APPROVED("Approved & Signed"),
    REJECTED("Rejected");

    private final String displayName;

    RequestStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() { return displayName; }
}