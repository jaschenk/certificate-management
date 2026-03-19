package com.certman.engine;

import com.certman.domain.KeyAlgorithm;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.SecureRandom;

/**
 * Generates cryptographic key pairs for RSA and EC algorithms.
 * Uses Bouncy Castle provider for FIPS-grade key generation.
 * 
 * Follows NIST SP 800-57 Part 1 Rev 5 for key length recommendations:
 * - RSA: 2048 (112-bit security), 4096 (≈140-bit security)
 * - EC: P-256 (128-bit), P-384 (192-bit), P-521 (256-bit)
 */
@Component
public class KeyPairGenerator {

    private static final Logger log = LoggerFactory.getLogger(KeyPairGenerator.class);
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generate a key pair for the specified algorithm.
     */
    public KeyPair generateKeyPair(KeyAlgorithm algorithm) {
        try {
            log.info("Generating {} key pair", algorithm.getDisplayName());

            return switch (algorithm.getAlgorithm()) {
                case "RSA" -> generateRsaKeyPair(algorithm.getKeySize());
                case "EC" -> generateEcKeyPair(algorithm.getCurveName());
                default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm.getAlgorithm());
            };
        } catch (Exception e) {
            throw new CertificateEngineException("Failed to generate key pair for " + algorithm.getDisplayName(), e);
        }
    }

    private KeyPair generateRsaKeyPair(int keySize) throws Exception {
        java.security.KeyPairGenerator keyPairGen =
                java.security.KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGen.initialize(keySize, secureRandom);
        return keyPairGen.generateKeyPair();
    }

    private KeyPair generateEcKeyPair(String curveName) throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        java.security.KeyPairGenerator keyPairGen =
                java.security.KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGen.initialize(ecSpec, secureRandom);
        return keyPairGen.generateKeyPair();
    }
}