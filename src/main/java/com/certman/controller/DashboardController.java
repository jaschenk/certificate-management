package com.certman.controller;

import com.certman.domain.CertificateStatus;
import com.certman.dto.DashboardStats;
import com.certman.service.AuditService;
import com.certman.service.CertificateAuthorityService;
import com.certman.service.CertificateService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Dashboard controller providing the main overview page.
 */
@Controller
public class DashboardController {

    private final CertificateAuthorityService caService;
    private final CertificateService certificateService;
    private final AuditService auditService;

    public DashboardController(
            CertificateAuthorityService caService,
            CertificateService certificateService,
            AuditService auditService) {
        this.caService = caService;
        this.certificateService = certificateService;
        this.auditService = auditService;
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        DashboardStats stats = new DashboardStats(
                caService.getAllCas().size(),
                caService.countByStatus(CertificateStatus.ACTIVE),
                certificateService.getAllCertificates().size(),
                certificateService.countByStatus(CertificateStatus.ACTIVE),
                certificateService.countByStatus(CertificateStatus.EXPIRED),
                certificateService.countByStatus(CertificateStatus.REVOKED),
                certificateService.countPendingRequests(),
                certificateService.getExpiringCertificates(30).size(),
                certificateService.getExpiringCertificates(30)
        );

        model.addAttribute("stats", stats);
        model.addAttribute("recentActivity", auditService.getRecentActivity());
        model.addAttribute("expiringCerts", certificateService.getExpiringCertificates(30));
        model.addAttribute("activePage", "dashboard");
        return "dashboard/index";
    }
}