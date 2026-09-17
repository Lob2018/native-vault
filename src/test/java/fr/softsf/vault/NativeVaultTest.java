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

import fr.softsf.vault.exception.NativeVaultException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for NativeVault lifecycle and CRUD operations using char[] buffers exclusively. */
class NativeVaultTest {

    private NativeVault vault;

    /** Sets up the test environment before each test execution. */
    @BeforeEach
    void setUp() throws NativeVaultException {
        vault =
                new NativeVault(
                        new char[] {
                            'f', 'r', '.', 's', 'o', 'f', 't', 's', 'f', '.', 'm', 'y', 'a', 'p',
                            'p'
                        });
    }

    /** Cleans up the test environment after each test execution. */
    @AfterEach
    void tearDown() throws NativeVaultException {
        if (vault != null) {
            char[] key = NativeVault.getIntegrityTestKey();
            try {
                vault.removeSecret(key);
            } finally {
                Arrays.fill(key, '\0');
            }
        }
    }

    /** Tests storing and retrieving secrets using character array parameters. */
    @Test
    void givenCharArrayKeyAndSecret_whenSetAndGetSecret_thenSecretIsRetrieved()
            throws NativeVaultException {
        char[] key = NativeVault.getIntegrityTestKey();
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
        char[] key = NativeVault.getIntegrityTestKey();
        try {
            assertFalse(vault.hasSecret(key));
            Optional<char[]> retrieved = vault.getSecret(key);
            assertTrue(retrieved.isEmpty());
            assertFalse(vault.removeSecret(key));
        } catch (NativeVaultException e) {
            throw new RuntimeException(e);
        } finally {
            Arrays.fill(key, '\0');
        }
    }

    /** Tests removing a stored secret successfully using character array parameters. */
    @Test
    void givenStoredSecret_whenRemoveSecret_thenSecretIsDeleted() throws NativeVaultException {
        char[] key = NativeVault.getIntegrityTestKey();
        char[] secret = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
        try {
            assertTrue(vault.setSecret(key, secret));
            assertTrue(vault.hasSecret(key));
            assertTrue(vault.removeSecret(key));
            assertFalse(vault.hasSecret(key));
        } finally {
            Arrays.fill(key, '\0');
            Arrays.fill(secret, '\0');
        }
    }

    /** Tests updating an existing secret successfully using character array parameters. */
    @Test
    void givenExistingSecret_whenUpdateSecret_thenSecretIsUpdated() throws NativeVaultException {
        char[] key = NativeVault.getIntegrityTestKey();
        char[] initialSecret = new char[] {'i', 'n', 'i', 't'};
        char[] updatedSecret = new char[] {'u', 'p', 'd', 'a', 't', 'e', 'd'};
        try {
            assertTrue(vault.setSecret(key, initialSecret));
            assertTrue(vault.setSecret(key, updatedSecret));
            Optional<char[]> retrieved = vault.getSecret(key);
            assertTrue(retrieved.isPresent());
            assertArrayEquals(updatedSecret, retrieved.get());
            Arrays.fill(retrieved.get(), '\0');
        } finally {
            Arrays.fill(key, '\0');
            Arrays.fill(initialSecret, '\0');
            Arrays.fill(updatedSecret, '\0');
        }
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
        assertThrows(IllegalArgumentException.class, () -> vault.removeSecret(null));
        assertThrows(IllegalArgumentException.class, () -> vault.hasSecret(emptyArray));
    }

    /**
     * Tests that a key exceeding maximum allowed length throws NativeVaultException encapsulating
     * IllegalArgumentException.
     */
    @Test
    void givenTooLongKey_whenSetSecret_thenIllegalArgumentExceptionIsThrown() {
        char[] longKey = new char[257];
        Arrays.fill(longKey, 'a');
        try {
            NativeVaultException ex =
                    assertThrows(
                            NativeVaultException.class,
                            () -> vault.setSecret(longKey, new char[] {'s'}));
            org.junit.jupiter.api.Assertions.assertInstanceOf(
                    IllegalArgumentException.class, ex.getCause());
        } finally {
            Arrays.fill(longKey, '\0');
        }
    }

    /**
     * Tests that a secret exceeding platform maximum allowed size throws NativeVaultException
     * encapsulating IllegalArgumentException.
     */
    @Test
    void givenTooLargeSecret_whenSetSecret_thenIllegalArgumentExceptionIsThrown() {
        char[] normalKey = new char[] {'k', 'e', 'y'};
        int size = System.getProperty("os.name").toLowerCase().contains("win") ? 3000 : 70000;
        char[] hugeSecret = new char[size];
        Arrays.fill(hugeSecret, 's');
        try {
            NativeVaultException ex =
                    assertThrows(
                            NativeVaultException.class,
                            () -> vault.setSecret(normalKey, hugeSecret));
            org.junit.jupiter.api.Assertions.assertInstanceOf(
                    IllegalArgumentException.class, ex.getCause());
        } finally {
            Arrays.fill(normalKey, '\0');
            Arrays.fill(hugeSecret, '\0');
        }
    }
}
