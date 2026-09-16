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
import java.util.Objects;
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;

/**
 * Polymorphic strategy interface for OS-native credential store operations using character arrays
 * for keys and secrets.
 */
public sealed interface VaultStrategy
        permits MacKeychainStrategy, LinuxKeyringStrategy, WindowsCredentialManagerStrategy {

    /**
     * Stores a secret in the native credential store.
     *
     * @param key the credential identifier character array
     * @param secret the secret character array
     * @return true if stored successfully, false otherwise
     * @throws IllegalArgumentException if {@code key} or {@code secret} is null or empty
     * @throws NativeVaultException if a native system error occurs during execution
     */
    boolean store(char[] key, char[] secret) throws NativeVaultException;

    /**
     * Retrieves a secret from the native credential store.
     *
     * @param key the credential identifier character array
     * @return an optional containing the secret character array if found
     * @throws IllegalArgumentException if {@code key} is null or empty
     * @throws NativeVaultException if a native system error occurs during execution
     */
    Optional<char[]> retrieve(char[] key) throws NativeVaultException;

    /**
     * Deletes a secret from the native credential store.
     *
     * @param key the credential identifier character array
     * @return true if deleted successfully, false otherwise
     * @throws IllegalArgumentException if {@code key} is null or empty
     * @throws NativeVaultException if a native system error occurs during execution
     */
    boolean delete(char[] key) throws NativeVaultException;

    /**
     * Checks if a secret exists in the native credential store.
     *
     * @param key the credential identifier character array
     * @return true if the secret exists, false otherwise
     * @throws IllegalArgumentException if {@code key} is null or empty
     * @throws NativeVaultException if a native system error occurs during execution
     */
    boolean exists(char[] key) throws NativeVaultException;

    /**
     * Overwrites the specified memory segment with zeros to ensure security.
     *
     * @param segment the memory segment to clear
     */
    default void zeroFill(MemorySegment segment) {
        if (segment != null && segment.address() != 0 && !segment.equals(MemorySegment.NULL)) {
            segment.fill((byte) 0);
        }
    }

    /**
     * Allocates and populates a memory segment for the given character data.
     *
     * @param arena the memory arena
     * @param data the character array data
     * @param charset the charset to use for encoding
     * @return the allocated memory segment
     * @throws NullPointerException if arena or charset is null
     * @throws IllegalArgumentException if data is null or empty
     */
    default MemorySegment allocateSegment(Arena arena, char[] data, Charset charset) {
        Objects.requireNonNull(arena, "Arena cannot be null");
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        Objects.requireNonNull(charset, "Charset cannot be null");
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
     * Detects and returns the appropriate native vault strategy based on the operating system.
     *
     * @return the matching vault strategy
     * @throws UnsupportedOperationException if the operating system is not supported
     */
    static VaultStrategy detect() {
        String os = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT);
        return switch (os) {
            case String s when s.contains("win") -> new WindowsCredentialManagerStrategy();
            case String s when s.contains("mac") -> new MacKeychainStrategy();
            case String s when s.contains("nix") || s.contains("nux") -> new LinuxKeyringStrategy();
            default ->
                    throw new UnsupportedOperationException("Unsupported operating system: " + os);
        };
    }
}
