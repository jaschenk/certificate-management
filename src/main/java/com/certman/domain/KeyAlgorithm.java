package com.certman.domain;

/**
 * Supported key pair algorithms per NIST SP 800-57 recommendations.
 */
public enum KeyAlgorithm {
    RSA_2048("RSA", 2048, "SHA256withRSA"),
    RSA_4096("RSA", 4096, "SHA384withRSA"),
    EC_P256("EC", 256, "SHA256withECDSA"),
    EC_P384("EC", 384, "SHA384withECDSA"),
    EC_P521("EC", 521, "SHA512withECDSA");

    private final String algorithm;
    private final int keySize;
    private final String defaultSignatureAlgorithm;

    KeyAlgorithm(String algorithm, int keySize, String defaultSignatureAlgorithm) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.defaultSignatureAlgorithm = defaultSignatureAlgorithm;
    }

    public String getAlgorithm() { return algorithm; }
    public int getKeySize() { return keySize; }
    public String getDefaultSignatureAlgorithm() { return defaultSignatureAlgorithm; }

    /**
     * Returns the EC curve name for EC algorithms, null for RSA.
     */
    public String getCurveName() {
        return switch (this) {
            case EC_P256 -> "secp256r1";
            case EC_P384 -> "secp384r1";
            case EC_P521 -> "secp521r1";
            default -> null;
        };
    }

    public String getDisplayName() {
        return switch (this) {
            case RSA_2048 -> "RSA 2048-bit";
            case RSA_4096 -> "RSA 4096-bit";
            case EC_P256 -> "ECDSA P-256";
            case EC_P384 -> "ECDSA P-384";
            case EC_P521 -> "ECDSA P-521";
        };
    }
}