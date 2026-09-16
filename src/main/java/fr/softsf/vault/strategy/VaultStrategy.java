/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;

/**
 * Polymorphic strategy interface for OS-native credential store operations using character arrays
 * for keys and secrets.
 */
public sealed interface VaultStrategy permits AbstractVaultStrategy {

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
}
