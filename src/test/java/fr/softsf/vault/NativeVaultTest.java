/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault;

import java.util.Arrays;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Unit tests for NativeVault lifecycle and CRUD operations using Given-When-Then convention. */
class NativeVaultTest {

    private NativeVault vault;

    /** Sets up the test environment before each test execution. */
    @BeforeEach
    void setUp() {
        assumeTrue(NativeVault.isUsable(), "Native vault is not operational on this platform.");
        vault = new NativeVault();
    }

    /** Cleans up the test environment after each test execution. */
    @AfterEach
    void tearDown() {
        if (vault != null) {
            vault.removeSecret(NativeVault.INTEGRITY_TEST_KEY);
            vault.close();
        }
    }

    /** Tests storing and retrieving secrets using string parameters. */
    @Test
    void givenStringKeyAndSecret_whenSetAndGetSecret_thenSecretIsRetrieved() {
        String secret = "test-secret-str";
        assertTrue(vault.setSecret(NativeVault.INTEGRITY_TEST_KEY, secret));
        assertTrue(vault.hasSecret(NativeVault.INTEGRITY_TEST_KEY));
        Optional<char[]> retrieved = vault.getSecret(NativeVault.INTEGRITY_TEST_KEY);
        assertTrue(retrieved.isPresent());
        assertArrayEquals(secret.toCharArray(), retrieved.get());
        Arrays.fill(retrieved.get(), '\0');
    }

    /** Tests storing and retrieving secrets using character array parameters. */
    @Test
    void givenCharArrayKeyAndSecret_whenSetAndGetSecret_thenSecretIsRetrieved() {
        char[] key = NativeVault.getIntegrityTestKeyChar();
        char[] secret = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
        try {
            assertTrue(vault.setSecret(key, secret));
            assertTrue(vault.hasSecret(key));
            Optional<char[]> retrieved = vault.getSecret(key);
            assertTrue(retrieved.isPresent());
            assertArrayEquals(secret, retrieved.get());
            Arrays.fill(retrieved.get(), '\0');
        } finally {
            Arrays.fill(key, '\0');
            Arrays.fill(secret, '\0');
        }
    }

    /** Tests behavior when querying a non-existent secret. */
    @Test
    void givenNonExistentKey_whenGetOrHasSecret_thenEmptyOrFalseIsReturned() {
        char[] key = NativeVault.getIntegrityTestKeyChar();
        try {
            assertFalse(vault.hasSecret(key));
            Optional<char[]> retrieved = vault.getSecret(key);
            assertTrue(retrieved.isEmpty());
            assertFalse(vault.removeSecret(key));
        } finally {
            Arrays.fill(key, '\0');
        }
    }

    /** Tests removing a stored secret successfully. */
    @Test
    void givenStoredSecret_whenRemoveSecret_thenSecretIsDeleted() {
        String secret = "secret-to-remove";
        assertTrue(vault.setSecret(NativeVault.INTEGRITY_TEST_KEY, secret));
        assertTrue(vault.hasSecret(NativeVault.INTEGRITY_TEST_KEY));
        assertTrue(vault.removeSecret(NativeVault.INTEGRITY_TEST_KEY));
        assertFalse(vault.hasSecret(NativeVault.INTEGRITY_TEST_KEY));
    }

    /** Tests invalid string inputs throwing IllegalArgumentException. */
    @Test
    void givenBlankStringInputs_whenMethodsCalled_thenIllegalArgumentExceptionIsThrown() {
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret("", "secret"));
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret("key", ""));
        assertThrows(IllegalArgumentException.class, () -> vault.getSecret("  "));
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret((String) null));
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret((char[]) null));
        assertThrows(IllegalArgumentException.class, () -> vault.hasSecret(""));
    }

    /** Tests invalid character array inputs throwing IllegalArgumentException. */
    @Test
    void givenNullOrEmptyCharArrayInputs_whenMethodsCalled_thenIllegalArgumentExceptionIsThrown() {
        char[] emptyArray = new char[0];
        assertThrows(
                IllegalArgumentException.class,
                () -> vault.setSecret(emptyArray, new char[] {'s'}));
        assertThrows(IllegalArgumentException.class, () -> vault.setSecret(new char[] {'k'}, null));
        assertThrows(IllegalArgumentException.class, () -> vault.getSecret(emptyArray));
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret((char[]) null));
        assertThrows(IllegalArgumentException.class, () -> vault.hasSecret(emptyArray));
    }
}
