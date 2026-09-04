/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.strategy.VaultStrategy;

/**
 * Facade class managing native credential operations using the FFM API with secure char[] handling
 * for both keys and secrets, dynamic strategy detection, and logging.
 */
public final class NativeVault implements AutoCloseable {
    static final String INTEGRITY_TEST_KEY = "fr.softsf.vault.integrity.check.key";

    static char[] getIntegrityTestKeyChar() {
        return INTEGRITY_TEST_KEY.toCharArray();
    }

    private static final VaultStrategy STRATEGY = VaultStrategy.detect();

    private final Arena arena;

    /** Initializes a new instance of the native vault facade. */
    public NativeVault() {
        ensureUsable();
        this.arena = Arena.ofConfined();
    }

    /** Holder class providing thread-safe lazy execution of the integrity check. */
    private static final class IntegrityHolder {
        private static final boolean VERIFIED = executeIntegrityCheck();

        private static boolean executeIntegrityCheck() {
            char[] testKey = getIntegrityTestKeyChar();
            char[] testValue = {'t', 'e', 's', 't'};
            try (Arena tempArena = Arena.ofConfined()) {
                MemorySegment segment = allocateSegment(tempArena, testValue);
                boolean stored = STRATEGY.store(testKey, segment, tempArena);
                boolean exists = STRATEGY.exists(testKey);
                Optional<MemorySegment> retrieved = STRATEGY.retrieve(testKey, tempArena);
                boolean deleted = STRATEGY.delete(testKey);
                return stored && exists && retrieved.isPresent() && deleted;
            } catch (Throwable t) { // NOSONAR
                if (t instanceof Error error) {
                    throw error;
                }
                return false;
            } finally {
                Arrays.fill(testKey, '\0');
                Arrays.fill(testValue, '\0');
            }
        }
    }

    /**
     * Checks if a native vault strategy is available and verified.
     *
     * @return true if a strategy is detected and operational, false otherwise
     */
    public static boolean isUsable() {
        return IntegrityHolder.VERIFIED;
    }

    /** Ensures that a strategy is available before performing operations. */
    private static void ensureUsable() {
        if (!isUsable()) {
            throw new NativeVaultException(
                    "Native vault is not usable: Strategy not detected or integrity check failed.",
                    null);
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
    public boolean setSecret(String key, String secret) {
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
    public boolean setSecret(char[] key, char[] secret) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }
        ensureUsable();
        MemorySegment segment = allocateSegment(arena, secret);
        try {
            return STRATEGY.store(key, segment, arena);
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to store secret in native store", t);
        } finally {
            zeroFill(segment);
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
    public Optional<char[]> getSecret(String key) {
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
    public Optional<char[]> getSecret(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        ensureUsable();
        try {
            Optional<MemorySegment> segmentOpt = STRATEGY.retrieve(key, arena);
            if (segmentOpt.isEmpty()) {
                return Optional.empty();
            }
            return segmentOpt.map(
                    segment -> {
                        try {
                            byte[] bytes = segment.toArray(ValueLayout.JAVA_BYTE);
                            CharBuffer charBuffer =
                                    StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
                            char[] chars = new char[charBuffer.remaining()];
                            charBuffer.get(chars);
                            Arrays.fill(bytes, (byte) 0);
                            return chars;
                        } finally {
                            zeroFill(segment);
                        }
                    });
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
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
    public boolean removeSecret(String key) {
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
    public boolean removeSecret(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        ensureUsable();
        try {
            return STRATEGY.delete(key);
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
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
    public boolean hasSecret(String key) {
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
    public boolean hasSecret(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        ensureUsable();
        try {
            return STRATEGY.exists(key);
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to check secret existence in native store", t);
        }
    }

    /**
     * Allocates a memory segment from a character array and encodes it to UTF-8.
     *
     * @param arena the memory arena
     * @param data the character array data
     * @return the allocated memory segment
     * @throws IllegalArgumentException if {@code arena} is null or {@code data} is null or empty
     */
    private static MemorySegment allocateSegment(Arena arena, char[] data) {
        if (Objects.isNull(arena)) {
            throw new IllegalArgumentException("Arena cannot be null or empty");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(data));
        MemorySegment segment = arena.allocate(byteBuffer.remaining());
        segment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
        byteBuffer.position(0);
        while (byteBuffer.hasRemaining()) {
            byteBuffer.put((byte) 0);
        }
        return segment;
    }

    /**
     * Overwrites the specified memory segment with zeros to ensure security.
     *
     * @param segment the memory segment to clear
     * @throws IllegalArgumentException if {@code segment} is null
     */
    private void zeroFill(MemorySegment segment) {
        if (Objects.isNull(segment)) {
            throw new IllegalArgumentException("Segment cannot be null or empty");
        }
        segment.fill((byte) 0);
    }

    /** Closes the native vault arena, releasing associated native memory resources. */
    @Override
    public void close() {
        arena.close();
    }
}
