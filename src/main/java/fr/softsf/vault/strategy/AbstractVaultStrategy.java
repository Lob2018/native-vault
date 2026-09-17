/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Objects;

public abstract sealed class AbstractVaultStrategy implements VaultStrategy
        permits MacKeychainStrategy, LinuxKeyringStrategy, WindowsCredentialManagerStrategy {

    /** Maximum allowed size in bytes for the identifier key across all platform strategies. */
    static final int MAX_KEY_BYTE_SIZE = 256;

    /** Maximum allowed size in bytes for the macOS Keychain Services secret payload. */
    static final long MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE = 1024L * 64L;

    /** Maximum allowed size in bytes for the Linux Secret Service DBus backend secret payload. */
    static final long LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE = 1024L * 64L;

    /** Maximum allowed size in bytes imposed by the Win32 Credential Manager CredWrite API. */
    static final int WINDOWS_CREDENTIAL_MANAGER_MAX_SECRET_BYTE_SIZE = 2560;

    /**
     * Validates the key constraints.
     *
     * @param key the key to validate
     * @throws IllegalArgumentException if the key is null, empty, or exceeds size limits
     */
    final void validateKey(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        if (key.length > MAX_KEY_BYTE_SIZE) {
            throw new IllegalArgumentException(
                    "Key exceeds maximum allowed length of " + MAX_KEY_BYTE_SIZE);
        }
    }

    /**
     * Validates the secret constraints based on the specific platform strategy implementation.
     *
     * @param secret the secret to validate
     * @throws IllegalArgumentException if the secret is null, empty, or exceeds platform limits
     */
    final void validateSecret(char[] secret) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }
        long limit =
                switch (this) {
                    case WindowsCredentialManagerStrategy _ ->
                            WINDOWS_CREDENTIAL_MANAGER_MAX_SECRET_BYTE_SIZE;
                    case MacKeychainStrategy _ -> MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE;
                    case LinuxKeyringStrategy _ -> LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE;
                };
        if (secret.length > limit) {
            throw new IllegalArgumentException("Secret exceeds maximum allowed length of " + limit);
        }
    }

    /**
     * Overwrites the specified memory segment with zeros to ensure security.
     *
     * @param segment the memory segment to clear
     */
    final void zeroFill(MemorySegment segment) {
        if (segment != null && segment.address() != 0 && !segment.equals(MemorySegment.NULL)) {
            segment.fill((byte) 0);
        }
    }

    /**
     * Overwrites the specified character array with zeros to ensure security.
     *
     * @param array the character array to clear
     */
    final void zeroFill(char[] array) {
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
    final MemorySegment allocateSegment(Arena arena, char[] data, Charset charset) {
        if (Objects.isNull(arena)) {
            throw new IllegalArgumentException("Arena cannot be null");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (Objects.isNull(charset)) {
            throw new IllegalArgumentException("Charset cannot be null");
        }
        java.nio.ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(data));
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
    final char[] concatNamespaceAndKey(char[] namespace, char[] key) {
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
