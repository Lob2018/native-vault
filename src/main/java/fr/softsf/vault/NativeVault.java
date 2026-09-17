/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault;

import java.util.Arrays;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.strategy.LinuxKeyringStrategy;
import fr.softsf.vault.strategy.MacKeychainStrategy;
import fr.softsf.vault.strategy.VaultStrategy;
import fr.softsf.vault.strategy.WindowsCredentialManagerStrategy;

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
 * // Unique namespace to avoid OS keychain collisions
 * char[] namespace = {'f', 'r', '.', 's', 'o', 'f', 't', 's', 'f', '.',
 *     'm', 'y', 'a', 'p', 'p'};
 * // The unique key to store
 * char[] key = {'u', 'n', 'i', 'q', 'u', 'e', 'k', 'e', 'y'};
 * // The secret to store
 * char[] secret = {'m', 'y', '-', 'c', 'r', 'i', 't', 'i', 'c', 'a', 'l',
 *     '-', 's', 'e', 'c', 'r', 'e', 't'};
 * try {
 *     // Initialize the native vault facade
 *     NativeVault vault = new NativeVault(namespace);
 *     // Upsert action: returns true if successfully stored, false otherwise
 *     boolean stored = vault.setSecret(key, secret);
 *     // Existence action: returns true if the secret exists, false otherwise
 *     boolean exists = vault.hasSecret(key);
 *     // Read action: returns Optional<char[]>
 *     vault.getSecret(key).ifPresent(rawSecret -> {
 *         try {
 *             // Process secret...
 *         } finally {
 *             Arrays.fill(rawSecret, '\0'); // Mandatory cleanup for secret buffer
 *         }
 *     });
 *     // Deletion action: returns true if successfully removed, false otherwise
 *     boolean removed = vault.removeSecret(key);
 * } catch (NativeVaultException | LinkageError e) {
 *     // Handle initialization or execution failures safely
 *     System.err.println("Failed to initialize or use native vault: " + e.getMessage());
 * } finally {
 *     Arrays.fill(namespace, '\0'); // Mandatory cleanup for namespace buffer
 *     Arrays.fill(key, '\0'); // Mandatory cleanup for key buffer
 *     Arrays.fill(secret, '\0'); // Mandatory cleanup for secret buffer
 * }
 * }</pre>
 */
public final class NativeVault {
    private static final Object INTEGRITY_CHECK_LOCK = new Object();

    static final String INTEGRITY_TEST_KEY = "key";

    /**
     * Returns the integrity test key character array.
     *
     * @return the integrity test key as a character array
     */
    static char[] getIntegrityTestKey() {
        return INTEGRITY_TEST_KEY.toCharArray();
    }

    private final VaultStrategy strategy;
    private final boolean verified;
    private final NativeVaultException initializationException;

    /**
     * Initializes a new instance of the native vault facade with a custom namespace.
     *
     * @param namespace the isolated namespace character array used as a schema name on Linux or a
     *     TargetName prefix on Windows/macOS
     * @throws IllegalArgumentException if {@code namespace} is null or empty
     * @throws NativeVaultException if the strategy integrity check fails
     * @throws UnsupportedOperationException if the operating system is not supported
     * @throws LinkageError if native library loading or linking fails
     */
    public NativeVault(char[] namespace) throws NativeVaultException {
        if (namespace == null || namespace.length == 0) {
            throw new IllegalArgumentException("Namespace cannot be null or empty");
        }
        VaultStrategy detectedStrategy = null;
        boolean isVerified = false;
        NativeVaultException initEx = null;
        try {
            detectedStrategy = detect(namespace);
            isVerified = executeIntegrityCheck(detectedStrategy);
        } catch (NativeVaultException e) {
            initEx = e;
        } catch (Exception e) {
            initEx = new NativeVaultException("Failed to initialize native vault strategy", e);
        }
        this.strategy = detectedStrategy;
        this.verified = isVerified;
        this.initializationException = initEx;
        ensureUsable();
    }

    /**
     * Detects and returns the appropriate native vault strategy based on the operating system.
     *
     * @param namespace the isolated namespace character array used as a schema name on Linux or a
     *     TargetName prefix on Windows/macOS
     * @return the matching vault strategy
     * @throws IllegalArgumentException if {@code namespace} is null or empty
     * @throws UnsupportedOperationException if the operating system is not supported
     */
    private static VaultStrategy detect(char[] namespace) {
        if (namespace == null || namespace.length == 0) {
            throw new IllegalArgumentException("Namespace cannot be null or empty");
        }
        String os = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT);
        return switch (os) {
            case String s when s.contains("win") -> new WindowsCredentialManagerStrategy(namespace);
            case String s when s.contains("mac") -> new MacKeychainStrategy(namespace);
            case String s when s.contains("nix") || s.contains("nux") ->
                    new LinuxKeyringStrategy(namespace);
            default ->
                    throw new UnsupportedOperationException("Unsupported operating system: " + os);
        };
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
        char[] testKey = getIntegrityTestKey();
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
    private void ensureUsable() throws NativeVaultException {
        if (!verified || strategy == null) {
            String message =
                    initializationException != null
                            ? initializationException.getMessage()
                            : "Integrity verification returned false.";
            throw new NativeVaultException(
                    "Native vault is not usable: " + message, initializationException);
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
            return strategy.store(key, secret);
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
            return strategy.retrieve(key);
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
            return strategy.delete(key);
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
            return strategy.exists(key);
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
