package com.certman.controller;

import com.certman.domain.CertificateAuthority;
import com.certman.service.CertificateAuthorityService;
import com.certman.service.CrlService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST API controller for programmatic access.
 * Provides CRL distribution endpoint and machine-readable APIs.
 */
@RestController
@RequestMapping("/api/v1")
public class ApiController {

    private final CertificateAuthorityService caService;
    private final CrlService crlService;

    public ApiController(
            CertificateAuthorityService caService,
            CrlService crlService) {
        this.caService = caService;
        this.crlService = crlService;
    }

    /**
     * CRL Distribution Point - serves DER-encoded CRL for a CA.
     * This is the URL embedded in certificates as the CRL Distribution Point.
     */
    @GetMapping("/crl/{caId}")
    public ResponseEntity<byte[]> getCrl(@PathVariable UUID caId) {
        CertificateAuthority ca = caService.getCaById(caId)
                .orElseThrow(() -> new IllegalArgumentException("CA not found: " + caId));

        byte[] crlDer = crlService.getCrlDer(ca);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=&quot;" + ca.getName() + ".crl&quot;")
                .contentType(MediaType.parseMediaType("application/pkix-crl"))
                .body(crlDer);
    }

    /**
     * Get CA certificate in PEM format.
     */
    @GetMapping("/ca/{caId}/certificate")
    public ResponseEntity<String> getCaCertificate(@PathVariable UUID caId) {
        CertificateAuthority ca = caService.getCaById(caId)
                .orElseThrow(() -> new IllegalArgumentException("CA not found: " + caId));

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(ca.getCertificatePem());
    }

    /**
     * Health check endpoint.
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("{&quot;status&quot;:&quot;UP&quot;,&quot;service&quot;:&quot;CertMan&quot;}");
    }
}