package com.certman.controller;

import com.certman.domain.*;
import com.certman.service.CertificateAuthorityService;
import com.certman.service.CertificateService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/**
 * Web controller for certificate management pages.
 */
@Controller
@RequestMapping("/certificates")
public class CertificateController {

    private final CertificateService certificateService;
    private final CertificateAuthorityService caService;

    public CertificateController(
            CertificateService certificateService,
            CertificateAuthorityService caService) {
        this.certificateService = certificateService;
        this.caService = caService;
    }

    @GetMapping
    public String listCertificates(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) CertificateStatus status,
            Model model) {

        if (search != null && !search.isBlank()) {
            model.addAttribute("certificates", certificateService.searchByCommonName(search));
            model.addAttribute("search", search);
        } else if (status != null) {
            model.addAttribute("certificates", certificateService.getCertificatesByStatus(status));
            model.addAttribute("filterStatus", status);
        } else {
            model.addAttribute("certificates", certificateService.getAllCertificates());
        }

        model.addAttribute("statuses", CertificateStatus.values());
        model.addAttribute("activePage", "certificates");
        return "certificate/list";
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("activeCas", caService.getActiveCas());
        model.addAttribute("certificateTypes", CertificateType.values());
        model.addAttribute("keyAlgorithms", KeyAlgorithm.values());
        model.addAttribute("activePage", "certificates");
        return "certificate/create";
    }

    @PostMapping("/create")
    public String createCertificate(
            @RequestParam UUID issuingCaId,
            @RequestParam String commonName,
            @RequestParam(required = false) String organization,
            @RequestParam(required = false) String organizationalUnit,
            @RequestParam(required = false) String locality,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String country,
            @RequestParam(required = false) String subjectAltNames,
            @RequestParam CertificateType certificateType,
            @RequestParam KeyAlgorithm keyAlgorithm,
            @RequestParam(defaultValue = "365") int validityDays,
            RedirectAttributes redirectAttributes) {

        try {
            Certificate cert = certificateService.issueCertificate(
                    issuingCaId, commonName, organization, organizationalUnit,
                    locality, state, country, subjectAltNames,
                    certificateType, keyAlgorithm, validityDays);

            redirectAttributes.addFlashAttribute("success",
                    "Certificate for '" + cert.getCommonName() + "' issued successfully");
            return "redirect:/certificates/" + cert.getId();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to issue certificate: " + e.getMessage());
            return "redirect:/certificates/create";
        }
    }

    @GetMapping("/{id}")
    public String viewCertificate(@PathVariable UUID id, Model model) {
        Certificate cert = certificateService.getCertificateById(id)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found: " + id));

        model.addAttribute("cert", cert);
        model.addAttribute("revocationReasons", RevocationReason.values());
        model.addAttribute("activePage", "certificates");
        return "certificate/detail";
    }

    @PostMapping("/{id}/revoke")
    public String revokeCertificate(
            @PathVariable UUID id,
            @RequestParam RevocationReason reason,
            RedirectAttributes redirectAttributes) {

        try {
            Certificate cert = certificateService.revokeCertificate(id, reason);
            redirectAttributes.addFlashAttribute("success",
                    "Certificate '" + cert.getCommonName() + "' has been revoked");
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to revoke certificate: " + e.getMessage());
        }
        return "redirect:/certificates/" + id;
    }

    @PostMapping("/{id}/renew")
    public String renewCertificate(
            @PathVariable UUID id,
            @RequestParam(defaultValue = "365") int validityDays,
            RedirectAttributes redirectAttributes) {

        try {
            Certificate renewed = certificateService.renewCertificate(id, validityDays);
            redirectAttributes.addFlashAttribute("success",
                    "Certificate renewed successfully. New certificate ID: " + renewed.getId());
            return "redirect:/certificates/" + renewed.getId();
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Failed to renew certificate: " + e.getMessage());
            return "redirect:/certificates/" + id;
        }
    }

    // --- Download Endpoints ---

    @GetMapping("/{id}/download/pem")
    public ResponseEntity<String> downloadPem(@PathVariable UUID id) {
        Certificate cert = certificateService.getCertificateById(id)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=&quot;" + cert.getCommonName() + ".pem&quot;")
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(cert.getCertificatePem());
    }

    @GetMapping("/{id}/download/chain")
    public ResponseEntity<String> downloadChain(@PathVariable UUID id) {
        String chain = certificateService.exportCertificateChainPem(id);
        Certificate cert = certificateService.getCertificateById(id).orElseThrow();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=&quot;" + cert.getCommonName() + "-chain.pem&quot;")
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(chain);
    }

    @GetMapping("/{id}/download/der")
    public ResponseEntity<byte[]> downloadDer(@PathVariable UUID id) {
        byte[] der = certificateService.exportCertificateDer(id);
        Certificate cert = certificateService.getCertificateById(id).orElseThrow();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=&quot;" + cert.getCommonName() + ".der&quot;")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(der);
    }

    @PostMapping("/{id}/download/pkcs12")
    public ResponseEntity<byte[]> downloadPkcs12(
            @PathVariable UUID id,
            @RequestParam String password) {

        byte[] pkcs12 = certificateService.exportAsPkcs12(id, password);
        Certificate cert = certificateService.getCertificateById(id).orElseThrow();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=&quot;" + cert.getCommonName() + ".p12&quot;")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(pkcs12);
    }

    @GetMapping("/{id}/download/key")
    public ResponseEntity<String> downloadPrivateKey(@PathVariable UUID id) {
        Certificate cert = certificateService.getCertificateById(id)
                .orElseThrow(() -> new IllegalArgumentException("Certificate not found"));

        if ("EXTERNAL_CSR_NO_PRIVATE_KEY".equals(cert.getPrivateKeyPem())) {
            return ResponseEntity.badRequest().body("No private key available for this certificate");
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=&quot;" + cert.getCommonName() + "-key.pem&quot;")
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(cert.getPrivateKeyPem());
    }
}