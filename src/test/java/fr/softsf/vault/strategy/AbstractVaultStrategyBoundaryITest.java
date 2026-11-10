/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import fr.softsf.vault.NativeVault;
import fr.softsf.vault.exception.NativeVaultException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Unit tests for strategy boundary conditions using package-private constants. */
class AbstractVaultStrategyBoundaryITest {

    private static final String OS_NAME = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    private static final boolean IS_WINDOWS = OS_NAME.contains("win");
    private static final boolean IS_MAC = OS_NAME.contains("mac");
    private static final boolean IS_LINUX = OS_NAME.contains("lin");

    private NativeVault vault;
    private char[] maxKey;
    private long maxSecretSize;

    /** Sets up the test environment before each test execution. */
    @BeforeEach
    void setUp() throws NativeVaultException {
        char[] namespace = {
            'f', 'r', '.', 's', 'o', 'f', 't', 's', 'f', '.', 'm', 'y', 'a', 'p', 'p'
        };
        vault = new NativeVault(namespace);

        int maxKeyChars =
                IS_WINDOWS
                        ? AbstractVaultStrategy.MAX_KEY_BYTE_SIZE / 2
                        : AbstractVaultStrategy.MAX_KEY_BYTE_SIZE;
        int maxUserKeyLength = maxKeyChars - (IS_LINUX ? 0 : (namespace.length + 1));

        maxKey = new char[maxUserKeyLength];
        Arrays.fill(maxKey, 'k');

        maxSecretSize =
                IS_WINDOWS
                        ? AbstractVaultStrategy.WINDOWS_CREDENTIAL_MANAGER_MAX_SECRET_BYTE_SIZE / 2
                        : IS_MAC
                                ? AbstractVaultStrategy.MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE
                                : AbstractVaultStrategy.LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE;

        try {
            vault.removeSecret(maxKey);
        } catch (Exception _) {
            // Ignored because the secret may not exist yet during initial setup
        }
    }

    /** Cleans up the test environment after each test execution. */
    @AfterEach
    void tearDown() throws NativeVaultException {
        if (vault != null && maxKey != null) {
            try {
                vault.removeSecret(maxKey);
            } finally {
                Arrays.fill(maxKey, '\0');
            }
        }
    }

    /** Tests boundary conditions for maximum exact valid key and secret sizes across platforms. */
    @Test
    void givenMaxExactValidKeyAndSecret_whenSetSecret_thenSuccess() throws NativeVaultException {
        char[] maxSecret = new char[(int) maxSecretSize];
        Arrays.fill(maxSecret, 's');

        try {
            vault.setSecret(maxKey, maxSecret);
            Optional<char[]> retrieved = vault.getSecret(maxKey);
            assertTrue(retrieved.isPresent());
            assertArrayEquals(maxSecret, retrieved.get());
            Arrays.fill(retrieved.get(), '\0');
        } finally {
            Arrays.fill(maxSecret, '\0');
        }
    }

    /** Tests that exceeding the maximum valid key boundary throws NativeVaultException. */
    @Test
    void givenExceedingMaxKeySize_whenSetSecret_thenThrowException() {
        char[] invalidKey = new char[maxKey.length + 1];
        Arrays.fill(invalidKey, 'k');
        char[] validSecret = {'s'};

        try {
            NativeVaultException ex =
                    assertThrows(
                            NativeVaultException.class,
                            () -> vault.setSecret(invalidKey, validSecret));
            assertInstanceOf(IllegalArgumentException.class, ex.getCause());
        } finally {
            Arrays.fill(invalidKey, '\0');
            Arrays.fill(validSecret, '\0');
        }
    }

    /** Tests that exceeding the platform maximum secret boundary throws NativeVaultException. */
    @Test
    void givenExceedingMaxSecretSize_whenSetSecret_thenThrowException() {
        char[] normalKey = {'k'};
        char[] tooLargeSecret = new char[(int) maxSecretSize + 1];
        Arrays.fill(tooLargeSecret, 's');

        try {
            NativeVaultException ex =
                    assertThrows(
                            NativeVaultException.class,
                            () -> vault.setSecret(normalKey, tooLargeSecret));
            assertInstanceOf(IllegalArgumentException.class, ex.getCause());
        } finally {
            Arrays.fill(normalKey, '\0');
            Arrays.fill(tooLargeSecret, '\0');
        }
    }
}
