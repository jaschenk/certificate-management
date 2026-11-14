package com.certman.engine;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Generates X.509 certificate serial numbers.
 *
 * Serial numbers are random rather than sequential so that they are unique
 * across every CA managed by this service (the serial_number columns carry a
 * table-wide unique constraint) and are not predictable.
 *
 * - RFC 5280 Section 4.1.2.2: positive integer, at most 20 octets
 * - CA/Browser Forum Baseline Requirements: at least 64 bits of CSPRNG output
 *
 * This generator produces 127 bits of entropy in at most 16 octets.
 */
@Component
public class SerialNumberGenerator {

    private static final int SERIAL_BYTES = 16;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * @return a random, strictly positive serial number
     */
    public BigInteger nextSerialNumber() {
        byte[] bytes = new byte[SERIAL_BYTES];
        BigInteger serial;
        do {
            secureRandom.nextBytes(bytes);
            bytes[0] &= 0x7F; // clear the top bit so the DER encoding stays within 16 octets
            serial = new BigInteger(1, bytes);
        } while (serial.signum() == 0);
        return serial;
    }
}
