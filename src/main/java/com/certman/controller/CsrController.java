package com.certman.controller;

import com.certman.domain.CertificateRequest;
import com.certman.domain.CertificateType;
import com.certman.service.CertificateAuthorityService;
import com.certman.service.CertificateService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/**
 * Web controller for Certificate Signing Request (CSR) management.
 */
@Controller
@RequestMapping("/csr")
public class CsrController {

    private final CertificateService certificateService;
    private final CertificateAuthorityService caService;

    public CsrController(
            CertificateService certificateService,
            CertificateAuthorityService caService) {
        this.certificateService = certificateService;
        this.caService = caService;
    }

    @GetMapping
    public String listRequests(Model model) {
        model.addAttribute("requests", certificateService.getAllRequests());
        model.addAttribute("pendingCount", certificateService.countPendingRequests());
        model.addAttribute("activePage", "csr");
        return "csr/list";
    }

    @GetMapping("/submit")
    public String showSubmitForm(Model model) {
        model.addAttribute("certificateTypes", CertificateType.values());
        model.addAttribute("activePage", "csr");
        return "csr/submit";
    }

    @PostMapping("/submit")
    public String submitCsr(
            @RequestParam String csrPem,
            @RequestParam String commonName,
            @RequestParam(required = false) String organization,
            @RequestParam(required = false) String organizationalUnit,
            @RequestParam(required = false) String locality,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String country,
            @RequestParam(required = false) String subjectAltNames,
            @RequestParam CertificateType requestedType,
            @RequestParam(defaultValue = "365") int validityDays,
            @RequestParam(required = false) String requesterName,
            @RequestParam(required = false) String requesterEmail,
            @RequestParam(required = false) String notes,
            RedirectAttributes redirectAttributes) {

        try {
            CertificateRequest request = certificateService.submitCsr(
                    csrPem, commonName, organization, organizationalUnit,
                    locality, state, country, subjectAltNames,
                    requestedType, validityDays, requesterName, requesterEmail, notes);

            redirectAttributes.addFlashAttribute("success",
                    "CSR submitted successfully. Request ID: " + request.getId());
            return "redirect:/csr/" + request.getId();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to submit CSR: " + e.getMessage());
            return "redirect:/csr/submit";
        }
    }

    @GetMapping("/{id}")
    public String viewRequest(@PathVariable UUID id, Model model) {
        CertificateRequest request = certificateService.getRequestById(id)
                .orElseThrow(() -> new IllegalArgumentException("CSR not found: " + id));

        model.addAttribute("request", request);
        model.addAttribute("activeCas", caService.getActiveCas());
        model.addAttribute("activePage", "csr");
        return "csr/detail";
    }

    @PostMapping("/{id}/approve")
    public String approveCsr(
            @PathVariable UUID id,
            @RequestParam UUID issuingCaId,
            @RequestParam(defaultValue = "365") int validityDays,
            RedirectAttributes redirectAttributes) {

        try {
            var cert = certificateService.signCertificateRequest(id, issuingCaId, validityDays);
            redirectAttributes.addFlashAttribute("success",
                    "CSR approved and certificate issued. Certificate ID: " + cert.getId());
            return "redirect:/certificates/" + cert.getId();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to approve CSR: " + e.getMessage());
            return "redirect:/csr/" + id;
        }
    }

    @PostMapping("/{id}/reject")
    public String rejectCsr(
            @PathVariable UUID id,
            @RequestParam String reason,
            RedirectAttributes redirectAttributes) {

        try {
            certificateService.rejectCertificateRequest(id, reason);
            redirectAttributes.addFlashAttribute("success", "CSR has been rejected");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to reject CSR: " + e.getMessage());
        }
        return "redirect:/csr/" + id;
    }
}