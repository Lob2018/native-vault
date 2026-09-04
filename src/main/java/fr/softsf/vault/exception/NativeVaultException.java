/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.exception;

/** Exception thrown when a native vault operation fails. */
public class NativeVaultException extends RuntimeException {

    /**
     * Constructs a new native vault exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the underlying cause
     */
    public NativeVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
