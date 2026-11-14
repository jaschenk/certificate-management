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

    // Register Bouncy Castle when this class is initialised rather than only in main(),
    // so the provider is also present when the context is started without main()
    // (e.g. @SpringBootTest, or a single test class run on its own).
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(CertManApplication.class, args);
    }
}