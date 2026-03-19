package com.certman.controller;

import com.certman.domain.CertificateAuthority;
import com.certman.domain.KeyAlgorithm;
import com.certman.service.CertificateAuthorityService;
import com.certman.service.CertificateService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/**
 * Web controller for Certificate Authority management pages.
 */
@Controller
@RequestMapping("/ca")
public class CertificateAuthorityController {

    private final CertificateAuthorityService caService;
    private final CertificateService certificateService;

    public CertificateAuthorityController(
            CertificateAuthorityService caService,
            CertificateService certificateService) {
        this.caService = caService;
        this.certificateService = certificateService;
    }

    @GetMapping
    public String listCas(Model model) {
        model.addAttribute("cas", caService.getAllCas());
        model.addAttribute("activePage", "ca");
        return "ca/list";
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("keyAlgorithms", KeyAlgorithm.values());
        model.addAttribute("rootCas", caService.getRootCas());
        model.addAttribute("activeCas", caService.getActiveCas());
        model.addAttribute("activePage", "ca");
        return "ca/create";
    }

    @PostMapping("/create")
    public String createCa(
            @RequestParam String name,
            @RequestParam String commonName,
            @RequestParam(required = false) String organization,
            @RequestParam(required = false) String organizationalUnit,
            @RequestParam(required = false) String locality,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String country,
            @RequestParam KeyAlgorithm keyAlgorithm,
            @RequestParam(defaultValue = "3650") int validityDays,
            @RequestParam(defaultValue = "-1") int pathLengthConstraint,
            @RequestParam(required = false) String parentCaId,
            RedirectAttributes redirectAttributes) {

        try {
            CertificateAuthority ca;
            if (parentCaId != null && !parentCaId.isBlank()) {
                ca = caService.createIntermediateCa(
                        name, commonName, organization, organizationalUnit,
                        locality, state, country, keyAlgorithm,
                        validityDays, pathLengthConstraint, UUID.fromString(parentCaId));
            } else {
                ca = caService.createRootCa(
                        name, commonName, organization, organizationalUnit,
                        locality, state, country, keyAlgorithm,
                        validityDays, pathLengthConstraint);
            }
            redirectAttributes.addFlashAttribute("success",
                    "Certificate Authority '" + ca.getName() + "' created successfully");
            return "redirect:/ca/" + ca.getId();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to create CA: " + e.getMessage());
            return "redirect:/ca/create";
        }
    }

    @GetMapping("/{id}")
    public String viewCa(@PathVariable UUID id, Model model) {
        CertificateAuthority ca = caService.getCaById(id)
                .orElseThrow(() -> new IllegalArgumentException("CA not found: " + id));

        model.addAttribute("ca", ca);
        model.addAttribute("issuedCerts", ca.getIssuedCertificates());
        model.addAttribute("childCas", ca.getChildCas());
        model.addAttribute("activePage", "ca");
        return "ca/detail";
    }

    @GetMapping("/{id}/certificate")
    @ResponseBody
    public String downloadCaCertificate(@PathVariable UUID id) {
        CertificateAuthority ca = caService.getCaById(id)
                .orElseThrow(() -> new IllegalArgumentException("CA not found: " + id));
        return ca.getCertificatePem();
    }
}