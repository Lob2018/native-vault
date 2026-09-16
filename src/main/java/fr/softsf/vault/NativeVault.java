/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.StringUtils;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.strategy.VaultStrategy;

/**
 * Zero-JNI/JNA facade class managing native credential operations via the Project Panama Foreign
 * Function & Memory (FFM) API. Designed exclusively for active user session secret stores in
 * desktop applications, featuring strict memory hygiene via {@code char[]} buffers and dynamic
 * strategy detection.
 *
 * <p>Keys and secrets must be managed as mutable {@code char[]} buffers and explicitly zero-filled
 * ({@code Arrays.fill(..., '\0')}) in a {@code finally} block to guarantee heap memory hygiene.
 *
 * <p>Interactions must be wrapped in a corresponding <b>catch (NativeVaultException |
 * LinkageError)</b> block to safely handle native linkage initialization and execution errors.
 *
 * <p><strong>Usage Example:</strong>
 *
 * <pre>{@code
 * char[] uniqueExampleKey = {'f', 'r', '.', 's', 'o', 'f', 't', 's', 'f', '.', 'm', 'y', 'a', 'p', 'p', '.', 'u', 'n', 'i', 'q', 'u', 'e', 'k', 'e', 'y'};
 * char[] secret = {'m', 'y', '-', 'c', 'r', 'i', 't', 'i', 'c', 'a', 'l', '-', 's', 'e', 'c', 'r', 'e', 't'};
 * try {
 *     NativeVault vault = new NativeVault();
 *     boolean stored = vault.setSecret(uniqueExampleKey, secret);
 *     boolean exists = vault.hasSecret(uniqueExampleKey);
 *     vault.getSecret(uniqueExampleKey).ifPresent(retrieved -> {
 *         java.util.Arrays.fill(retrieved, '\0');
 *     });
 *     boolean removed = vault.removeSecret(uniqueExampleKey);
 * } catch (NativeVaultException | LinkageError e) {
 *     System.err.println("Failed to initialize or use native vault: " + e.getMessage());
 * } finally {
 *     java.util.Arrays.fill(uniqueExampleKey, '\0');
 *     java.util.Arrays.fill(secret, '\0');
 * }
 * }</pre>
 */
public final class NativeVault {
    private static final Object INTEGRITY_CHECK_LOCK = new Object();
    static final String INTEGRITY_TEST_KEY = "fr.softsf.vault.integrity.check.key";

    static char[] getIntegrityTestKeyChar() {
        return INTEGRITY_TEST_KEY.toCharArray();
    }

    private static final VaultStrategy STRATEGY;
    private static final AtomicReference<NativeVaultException> INITIALIZATION_EXCEPTION =
            new AtomicReference<>();
    private static final boolean VERIFIED;

    static {
        VaultStrategy strategy = null;
        boolean verified = false;
        try {
            strategy = VaultStrategy.detect();
            verified = executeIntegrityCheck(strategy);
        } catch (NativeVaultException e) {
            INITIALIZATION_EXCEPTION.set(e);
        } catch (Exception e) {
            INITIALIZATION_EXCEPTION.set(
                    new NativeVaultException("Failed to initialize native vault strategy", e));
        }
        STRATEGY = strategy;
        VERIFIED = verified;
    }

    /**
     * Initializes a new instance of the native vault facade.
     *
     * @throws NativeVaultException if the strategy integrity check fails
     * @throws UnsupportedOperationException if the operating system is not supported
     * @throws LinkageError if native library loading or linking fails
     */
    public NativeVault() throws NativeVaultException {
        ensureUsable();
    }

    /**
     * Executes the native vault integrity check sequence within a synchronized block to prevent
     * race conditions on the shared test key.
     *
     * @param strategy the vault strategy instance to verify
     * @return true if store, existence, retrieval, and deletion operations succeed
     * @throws NativeVaultException if an error occurs during the integrity check execution
     */
    @SuppressWarnings("java:S1181")
    private static boolean executeIntegrityCheck(VaultStrategy strategy)
            throws NativeVaultException {
        if (strategy == null) {
            return false;
        }
        char[] testKey = getIntegrityTestKeyChar();
        char[] testValue = {'t', 'e', 's', 't'};
        synchronized (INTEGRITY_CHECK_LOCK) {
            try {
                boolean stored = strategy.store(testKey, testValue);
                boolean exists = strategy.exists(testKey);
                Optional<char[]> retrieved = strategy.retrieve(testKey);
                boolean deleted = strategy.delete(testKey);
                return stored && exists && retrieved.isPresent() && deleted;
            } catch (Throwable t) {
                if (t instanceof Error error) {
                    throw error;
                }
                if (t instanceof NativeVaultException nativeVaultException) {
                    throw nativeVaultException;
                }
                throw new NativeVaultException(
                        "Native vault integrity check failed during initialization", t);
            } finally {
                Arrays.fill(testKey, '\0');
                Arrays.fill(testValue, '\0');
            }
        }
    }

    /**
     * Ensures that a strategy is available before performing operations.
     *
     * @throws NativeVaultException if the integrity verification failed
     */
    private static void ensureUsable() throws NativeVaultException {
        if (!VERIFIED || STRATEGY == null) {
            NativeVaultException cause = INITIALIZATION_EXCEPTION.get();
            String message =
                    cause != null ? cause.getMessage() : "Integrity verification returned false.";
            throw new NativeVaultException("Native vault is not usable: " + message, cause);
        }
    }

    /**
     * Stores or updates a secret securely in the native credential store using string parameters.
     * This operation acts as an upsert: if the key already exists, its value is overwritten.
     *
     * @param key the credential identifier
     * @param secret the secret value to store
     * @return true if the secret was successfully stored, false otherwise
     * @throws IllegalArgumentException if {@code key} or {@code secret} is blank
     * @throws NativeVaultException if an error occurs while storing the secret
     */
    public boolean setSecret(String key, String secret) throws NativeVaultException {
        if (StringUtils.isBlank(key)) {
            throw new IllegalArgumentException("Key cannot be null or blank");
        }
        if (StringUtils.isBlank(secret)) {
            throw new IllegalArgumentException("Secret cannot be null or blank");
        }
        ensureUsable();
        char[] keyChars = key.toCharArray();
        char[] secretChars = secret.toCharArray();
        try {
            return setSecret(keyChars, secretChars);
        } finally {
            Arrays.fill(keyChars, '\0');
            Arrays.fill(secretChars, '\0');
        }
    }

    /**
     * Stores or updates a secret securely in the native credential store using character array
     * parameters. This operation acts as an upsert: if the key already exists, its value is
     * overwritten.
     *
     * @param key the credential identifier character array
     * @param secret the secret value character array to store
     * @return true if the secret was successfully stored, false otherwise
     * @throws IllegalArgumentException if {@code key} or {@code secret} is null or empty
     * @throws NativeVaultException if an error occurs while storing the secret
     */
    @SuppressWarnings("java:S1181")
    public boolean setSecret(char[] key, char[] secret) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }
        ensureUsable();
        try {
            return STRATEGY.store(key, secret);
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            if (t instanceof NativeVaultException nativeVaultException) {
                throw nativeVaultException;
            }
            throw new NativeVaultException("Failed to store secret in native store", t);
        }
    }

    /**
     * Retrieves a secret from the native credential store using a string key.
     *
     * @param key the credential identifier
     * @return an optional containing the secret character array if found
     * @throws IllegalArgumentException if {@code key} is blank
     * @throws NativeVaultException if an error occurs while retrieving the secret
     */
    public Optional<char[]> getSecret(String key) throws NativeVaultException {
        if (StringUtils.isBlank(key)) {
            throw new IllegalArgumentException("Key cannot be null or blank");
        }
        ensureUsable();
        char[] keyChars = key.toCharArray();
        try {
            return getSecret(keyChars);
        } finally {
            Arrays.fill(keyChars, '\0');
        }
    }

    /**
     * Retrieves a secret from the native credential store using a character array key.
     *
     * @param key the credential identifier character array
     * @return an optional containing the secret character array if found
     * @throws IllegalArgumentException if {@code key} is null or empty
     * @throws NativeVaultException if an error occurs while retrieving the secret
     */
    @SuppressWarnings("java:S1181")
    public Optional<char[]> getSecret(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        ensureUsable();
        try {
            return STRATEGY.retrieve(key);
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            if (t instanceof NativeVaultException nativeVaultException) {
                throw nativeVaultException;
            }
            throw new NativeVaultException("Failed to retrieve secret from native store", t);
        }
    }

    /**
     * Deletes a secret from the native credential store using a string key.
     *
     * @param key the credential identifier
     * @return true if the secret was successfully removed, false otherwise
     * @throws IllegalArgumentException if {@code key} is blank
     * @throws NativeVaultException if an error occurs while removing the secret
     */
    public boolean removeSecret(String key) throws NativeVaultException {
        if (StringUtils.isBlank(key)) {
            throw new IllegalArgumentException("Key cannot be null or blank");
        }
        ensureUsable();
        char[] keyChars = key.toCharArray();
        try {
            return removeSecret(keyChars);
        } finally {
            Arrays.fill(keyChars, '\0');
        }
    }

    /**
     * Deletes a secret from the native credential store using a character array key.
     *
     * @param key the credential identifier character array
     * @return true if the secret was successfully removed, false otherwise
     * @throws IllegalArgumentException if {@code key} is null or empty
     * @throws NativeVaultException if an error occurs while removing the secret
     */
    @SuppressWarnings("java:S1181")
    public boolean removeSecret(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        ensureUsable();
        try {
            return STRATEGY.delete(key);
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            if (t instanceof NativeVaultException nativeVaultException) {
                throw nativeVaultException;
            }
            throw new NativeVaultException("Failed to remove secret from native store", t);
        }
    }

    /**
     * Checks if a secret exists in the native credential store using a string key.
     *
     * @param key the credential identifier
     * @return true if the secret exists, false otherwise
     * @throws IllegalArgumentException if {@code key} is blank
     * @throws NativeVaultException if an error occurs while checking existence
     */
    public boolean hasSecret(String key) throws NativeVaultException {
        if (StringUtils.isBlank(key)) {
            throw new IllegalArgumentException("Key cannot be null or blank");
        }
        ensureUsable();
        char[] keyChars = key.toCharArray();
        try {
            return hasSecret(keyChars);
        } finally {
            Arrays.fill(keyChars, '\0');
        }
    }

    /**
     * Checks if a secret exists in the native credential store using a character array key.
     *
     * @param key the credential identifier character array
     * @return true if the secret exists, false otherwise
     * @throws IllegalArgumentException if {@code key} is null or empty
     * @throws NativeVaultException if an error occurs while checking existence
     */
    @SuppressWarnings("java:S1181")
    public boolean hasSecret(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        ensureUsable();
        try {
            return STRATEGY.exists(key);
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            if (t instanceof NativeVaultException nativeVaultException) {
                throw nativeVaultException;
            }
            throw new NativeVaultException("Failed to check secret existence in native store", t);
        }
    }
}
