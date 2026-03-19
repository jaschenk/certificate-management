package com.certman;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.security.Security;

/**
 * Certificate Management Service
 * 
 * Enterprise-grade PKI certificate lifecycle management built on:
 * - RFC 5280 (X.509 PKI Certificate and CRL Profile)
 * - RFC 2986 (PKCS #10: Certification Request Syntax)
 * - RFC 7292 (PKCS #12: Personal Information Exchange Syntax)
 * - RFC 5958 (Asymmetric Key Packages)
 * 
 * Supports RSA (2048/4096) and EC (P-256/P-384/P-521) key algorithms
 * with SHA-256/SHA-384/SHA-512 signature algorithms.
 */
@SpringBootApplication
@EnableScheduling
public class CertManApplication {

    public static void main(String[] args) {
        // Register Bouncy Castle as a security provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        SpringApplication.run(CertManApplication.class, args);
    }
}