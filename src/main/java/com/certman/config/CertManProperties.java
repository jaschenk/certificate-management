package com.certman.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Typed configuration properties for the Certificate Management Service.
 * Binds to the 'certman' prefix in application.yml.
 */
@Configuration
@ConfigurationProperties(prefix = "certman")
public class CertManProperties {

    private Defaults defaults = new Defaults();
    private Keystore keystore = new Keystore();
    private Crl crl = new Crl();

    public Defaults getDefaults() { return defaults; }
    public void setDefaults(Defaults defaults) { this.defaults = defaults; }
    public Keystore getKeystore() { return keystore; }
    public void setKeystore(Keystore keystore) { this.keystore = keystore; }
    public Crl getCrl() { return crl; }
    public void setCrl(Crl crl) { this.crl = crl; }

    public static class Defaults {
        private String keyAlgorithm = "RSA";
        private int keySize = 4096;
        private String signatureAlgorithm = "SHA384withRSA";
        private int validityDays = 365;
        private int caValidityDays = 3650;

        public String getKeyAlgorithm() { return keyAlgorithm; }
        public void setKeyAlgorithm(String keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }
        public int getKeySize() { return keySize; }
        public void setKeySize(int keySize) { this.keySize = keySize; }
        public String getSignatureAlgorithm() { return signatureAlgorithm; }
        public void setSignatureAlgorithm(String signatureAlgorithm) { this.signatureAlgorithm = signatureAlgorithm; }
        public int getValidityDays() { return validityDays; }
        public void setValidityDays(int validityDays) { this.validityDays = validityDays; }
        public int getCaValidityDays() { return caValidityDays; }
        public void setCaValidityDays(int caValidityDays) { this.caValidityDays = caValidityDays; }
    }

    public static class Keystore {
        private String basePath = "./data/keystores";

        public String getBasePath() { return basePath; }
        public void setBasePath(String basePath) { this.basePath = basePath; }
    }

    public static class Crl {
        private String distributionPoint = "http://localhost:8443/certman/api/v1/crl";
        private int updateIntervalHours = 24;

        public String getDistributionPoint() { return distributionPoint; }
        public void setDistributionPoint(String distributionPoint) { this.distributionPoint = distributionPoint; }
        public int getUpdateIntervalHours() { return updateIntervalHours; }
        public void setUpdateIntervalHours(int updateIntervalHours) { this.updateIntervalHours = updateIntervalHours; }
    }
}