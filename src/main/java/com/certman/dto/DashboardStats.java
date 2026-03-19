package com.certman.dto;

import com.certman.domain.Certificate;

import java.util.List;

/**
 * Dashboard statistics DTO for the overview page.
 */
public record DashboardStats(
        long totalCas,
        long activeCas,
        long totalCertificates,
        long activeCertificates,
        long expiredCertificates,
        long revokedCertificates,
        long pendingRequests,
        long expiringWithin30Days,
        List<Certificate> recentExpiring
) {}