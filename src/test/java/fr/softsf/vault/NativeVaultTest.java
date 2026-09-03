package fr.softsf.vault;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Unit tests for NativeVault lifecycle and CRUD operations using Given-When-Then convention.
 */
class NativeVaultTest {

    private NativeVault vault;

    /**
     * Sets up the test environment before each test execution.
     */
    @BeforeEach
    void setUp() {
        assumeTrue(NativeVault.isUsable(), "Native vault is not operational on this platform.");
        vault = new NativeVault();
    }

    /**
     * Cleans up the test environment after each test execution.
     */
    @AfterEach
    void tearDown() {
        if (vault != null) {
            vault.close();
        }
    }

    /**
     * Tests storing and retrieving secrets using string parameters.
     */
    @Test
    void givenStringKeyAndSecret_whenSetAndGetSecret_thenSecretIsRetrieved() {
        String key = "test-key-str";
        String secret = "test-secret-str";
        try {
            assertTrue(vault.setSecret(key, secret));
            assertTrue(vault.hasSecret(key));

            Optional<char[]> retrieved = vault.getSecret(key);
            assertTrue(retrieved.isPresent());
            assertArrayEquals(secret.toCharArray(), retrieved.get());
        } finally {
            vault.removeSecret(key);
        }
    }

    /**
     * Tests storing and retrieving secrets using character array parameters.
     */
    @Test
    void givenCharArrayKeyAndSecret_whenSetAndGetSecret_thenSecretIsRetrieved() {
        char[] key = new char[]{'t', 'e', 's', 't', '-', 'k', 'e', 'y', '-', 'c', 'h', 'a', 'r'};
        char[] secret = new char[]{'s', 'e', 'c', 'r', 'e', 't'};
        try {
            assertTrue(vault.setSecret(key, secret));
            assertTrue(vault.hasSecret(key));

            Optional<char[]> retrieved = vault.getSecret(key);
            assertTrue(retrieved.isPresent());
            assertArrayEquals(secret, retrieved.get());
        } finally {
            vault.removeSecret(key);
        }
    }

    /**
     * Tests behavior when querying a non-existent secret.
     */
    @Test
    void givenNonExistentKey_whenGetOrHasSecret_thenEmptyOrFalseIsReturned() {
        char[] key = new char[]{'n', 'o', 'n', '-', 'e', 'x', 'i', 's', 't'};
        assertFalse(vault.hasSecret(key));
        Optional<char[]> retrieved = vault.getSecret(key);
        assertTrue(retrieved.isEmpty());
        assertFalse(vault.removeSecret(key));
    }

    /**
     * Tests removing a stored secret successfully.
     */
    @Test
    void givenStoredSecret_whenRemoveSecret_thenSecretIsDeleted() {
        String key = "test-remove-key";
        String secret = "secret-to-remove";
        assertTrue(vault.setSecret(key, secret));
        assertTrue(vault.hasSecret(key));
        assertTrue(vault.removeSecret(key));
        assertFalse(vault.hasSecret(key));
    }

    /**
     * Tests invalid string inputs throwing IllegalArgumentException.
     */
    @Test
    void givenBlankStringInputs_whenMethodsCalled_thenIllegalArgumentExceptionIsThrown() {
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret("", "secret"));
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret("key", ""));
        assertThrows(IllegalArgumentException.class, () -> vault.getSecret("  "));
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret((String) null));
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret((char[]) null));
        assertThrows(IllegalArgumentException.class, () -> vault.hasSecret(""));
    }

    /**
     * Tests invalid character array inputs throwing IllegalArgumentException.
     */
    @Test
    void givenNullOrEmptyCharArrayInputs_whenMethodsCalled_thenIllegalArgumentExceptionIsThrown() {
        char[] emptyArray = new char[0];
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret(emptyArray, new char[]{'s'}));
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret(new char[]{'k'}, null));
        assertThrows(IllegalArgumentException.class, () -> vault.getSecret(emptyArray));
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret((char[]) null));
        assertThrows(IllegalArgumentException.class, () -> vault.hasSecret(emptyArray));
    }
}