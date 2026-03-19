package com.certman.engine;

/**
 * Exception thrown by certificate engine operations.
 */
public class CertificateEngineException extends RuntimeException {

    public CertificateEngineException(String message) {
        super(message);
    }

    public CertificateEngineException(String message, Throwable cause) {
        super(message, cause);
    }
}