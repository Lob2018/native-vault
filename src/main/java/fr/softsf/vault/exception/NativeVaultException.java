package fr.softsf.vault.exception;

/**
 * Exception thrown when a native vault operation fails.
 */
public class NativeVaultException extends RuntimeException {

    /**
     * Constructs a new native vault exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the underlying cause
     */
    public NativeVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}