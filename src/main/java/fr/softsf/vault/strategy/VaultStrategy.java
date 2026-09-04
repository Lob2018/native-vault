/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Optional;

/**
 * Polymorphic strategy interface for OS-native credential store operations using character arrays
 * for keys and boolean confirmations.
 */
public sealed interface VaultStrategy
        permits MacKeychainStrategy, LinuxKeyringStrategy, WindowsCredentialManagerStrategy {

    /**
     * Stores a secret in the native credential store.
     *
     * @param key the credential identifier character array
     * @param secretData the memory segment containing the secret data
     * @param arena the memory arena managing the segment
     * @return true if stored successfully, false otherwise
     */
    boolean store(char[] key, MemorySegment secretData, Arena arena);

    /**
     * Retrieves a secret from the native credential store.
     *
     * @param key the credential identifier character array
     * @param arena the memory arena for allocation
     * @return an optional containing the memory segment of the secret if found
     */
    Optional<MemorySegment> retrieve(char[] key, Arena arena);

    /**
     * Deletes a secret from the native credential store.
     *
     * @param key the credential identifier character array
     * @return true if deleted successfully, false otherwise
     */
    boolean delete(char[] key);

    /**
     * Checks if a secret exists in the native credential store.
     *
     * @param key the credential identifier character array
     * @return true if the secret exists, false otherwise
     */
    boolean exists(char[] key);

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
