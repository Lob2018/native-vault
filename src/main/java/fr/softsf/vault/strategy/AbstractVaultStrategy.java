/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

public abstract sealed class AbstractVaultStrategy implements VaultStrategy
        permits MacKeychainStrategy, LinuxKeyringStrategy, WindowsCredentialManagerStrategy {

    /** Cached platform check to avoid redundant system property lookups and string allocations. */
    private static final boolean IS_WINDOWS =
            System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");

    /** Maximum allowed size in bytes for the identifier key across all platform strategies. */
    static final int MAX_KEY_BYTE_SIZE = 256;

    /** Maximum allowed size in bytes for the macOS Keychain Services secret payload. */
    static final long MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE = 1024L * 64L;

    /** Maximum allowed size in bytes for the Linux Secret Service DBus backend secret payload. */
    static final long LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE = 1024L * 64L;

    /** Maximum allowed size in bytes imposed by the Win32 Credential Manager CredWrite API. */
    static final int WINDOWS_CREDENTIAL_MANAGER_MAX_SECRET_BYTE_SIZE = 2560;

    /**
     * Validates data array size constraints against a specified byte limit.
     *
     * @param data the character array to validate
     * @param limit the maximum allowed byte size
     * @param errorMessage the exception message if limit is exceeded
     */
    private static void validateDataSize(char[] data, long limit, String errorMessage) {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException(errorMessage + " cannot be null or empty");
        }
        Charset charset = IS_WINDOWS ? StandardCharsets.UTF_16LE : StandardCharsets.UTF_8;
        ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(data));
        try {
            if (byteBuffer.remaining() > limit) {
                throw new IllegalArgumentException(
                        errorMessage + " exceeds maximum allowed byte size of " + limit);
            }
        } finally {
            while (byteBuffer.hasRemaining()) {
                byteBuffer.put((byte) 0);
            }
        }
    }

    /**
     * Validates the key constraints.
     *
     * @param key the key to validate
     * @throws IllegalArgumentException if the key is null, empty, or exceeds size limits
     */
    static void validateKey(char[] key) {
        validateDataSize(key, MAX_KEY_BYTE_SIZE, "Key");
    }

    /**
     * Validates the secret constraints based on the specific platform strategy implementation.
     *
     * @param secret the secret to validate
     * @throws IllegalArgumentException if the secret is null, empty, or exceeds platform limits
     */
    final void validateSecret(char[] secret) {
        long limit =
                switch (this) {
                    case WindowsCredentialManagerStrategy _ ->
                            WINDOWS_CREDENTIAL_MANAGER_MAX_SECRET_BYTE_SIZE;
                    case MacKeychainStrategy _ -> MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE;
                    case LinuxKeyringStrategy _ -> LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE;
                };
        validateDataSize(secret, limit, "Secret");
    }

    /**
     * Overwrites the specified memory segment with zeros to ensure security.
     *
     * @param segment the memory segment to clear
     */
    static void zeroFill(MemorySegment segment) {
        if (segment != null && segment.address() != 0 && !segment.equals(MemorySegment.NULL)) {
            segment.fill((byte) 0);
        }
    }

    /**
     * Overwrites the specified character array with zeros to ensure security.
     *
     * @param array the character array to clear
     */
    static void zeroFill(char[] array) {
        if (array != null) {
            Arrays.fill(array, '\0');
        }
    }

    /**
     * Allocates and populates a memory segment for the given character data.
     *
     * @param arena the memory arena
     * @param data the character array data
     * @param charset the charset to use for encoding
     * @return the allocated memory segment
     * @throws IllegalArgumentException if {@code arena}, {@code data}, or {@code charset} is null,
     *     or if {@code data} is empty
     */
    static MemorySegment allocateSegment(Arena arena, char[] data, Charset charset) {
        if (Objects.isNull(arena)) {
            throw new IllegalArgumentException("Arena cannot be null");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (Objects.isNull(charset)) {
            throw new IllegalArgumentException("Charset cannot be null");
        }
        ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(data));
        MemorySegment segment = arena.allocate(byteBuffer.remaining());
        segment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
        byteBuffer.position(0);
        while (byteBuffer.hasRemaining()) {
            byteBuffer.put((byte) 0);
        }
        return segment;
    }

    /**
     * Concatenates the namespace and the user key with an intermediate dot separator and validates
     * all parts. Memory safety & hygiene: Caller is responsible for zero-filling the returned
     * array.
     *
     * @param namespace the namespace character array
     * @param key the user key character array
     * @return a new combined namespaced key array
     * @throws IllegalArgumentException if namespace, key, or the resulting combined key violates
     *     validation rules (null, empty, or exceeds maximum allowed length)
     */
    static char[] concatNamespaceAndKey(char[] namespace, char[] key) {
        validateKey(namespace);
        validateKey(key);
        char[] result = new char[namespace.length + 1 + key.length];
        System.arraycopy(namespace, 0, result, 0, namespace.length);
        result[namespace.length] = '.';
        System.arraycopy(key, 0, result, namespace.length + 1, key.length);
        validateKey(result);
        return result;
    }
}
