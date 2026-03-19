package com.certman.engine;

import com.certman.domain.KeyAlgorithm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KeyPairGenerator — validates key generation for all supported algorithms.
 */
@DisplayName("KeyPairGenerator Tests")
class KeyPairGeneratorTest {

    private final KeyPairGenerator generator = new KeyPairGenerator();

    @BeforeAll
    static void setup() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @ParameterizedTest(name = "Generate {0} key pair")
    @EnumSource(KeyAlgorithm.class)
    @DisplayName("Should generate valid key pairs for all supported algorithms")
    void shouldGenerateKeyPairForAllAlgorithms(KeyAlgorithm algorithm) {
        KeyPair keyPair = generator.generateKeyPair(algorithm);

        assertNotNull(keyPair, "KeyPair should not be null");
        assertNotNull(keyPair.getPublic(), "Public key should not be null");
        assertNotNull(keyPair.getPrivate(), "Private key should not be null");
        assertEquals(algorithm.getAlgorithm(), keyPair.getPublic().getAlgorithm(),
                "Public key algorithm should match");
    }

    @Test
    @DisplayName("RSA 4096 key should have correct key size")
    void rsaKeyShouldHaveCorrectSize() {
        KeyPair keyPair = generator.generateKeyPair(KeyAlgorithm.RSA_4096);
        RSAPublicKey rsaKey = (RSAPublicKey) keyPair.getPublic();

        assertEquals(4096, rsaKey.getModulus().bitLength(),
                "RSA key should be 4096 bits");
    }

    @Test
    @DisplayName("RSA 2048 key should have correct key size")
    void rsa2048KeyShouldHaveCorrectSize() {
        KeyPair keyPair = generator.generateKeyPair(KeyAlgorithm.RSA_2048);
        RSAPublicKey rsaKey = (RSAPublicKey) keyPair.getPublic();

        assertEquals(2048, rsaKey.getModulus().bitLength(),
                "RSA key should be 2048 bits");
    }

    @Test
    @DisplayName("EC P-256 key should use correct curve")
    void ecP256KeyShouldUseCorrectCurve() {
        KeyPair keyPair = generator.generateKeyPair(KeyAlgorithm.EC_P256);
        ECPublicKey ecKey = (ECPublicKey) keyPair.getPublic();

        assertNotNull(ecKey.getParams(), "EC parameters should not be null");
        assertEquals(256, ecKey.getParams().getOrder().bitLength(),
                "EC key order should be ~256 bits");
    }

    @Test
    @DisplayName("Each generated key pair should be unique")
    void generatedKeyPairsShouldBeUnique() {
        KeyPair kp1 = generator.generateKeyPair(KeyAlgorithm.RSA_2048);
        KeyPair kp2 = generator.generateKeyPair(KeyAlgorithm.RSA_2048);

        assertNotEquals(kp1.getPublic(), kp2.getPublic(),
                "Two generated key pairs should have different public keys");
        assertNotEquals(kp1.getPrivate(), kp2.getPrivate(),
                "Two generated key pairs should have different private keys");
    }
}