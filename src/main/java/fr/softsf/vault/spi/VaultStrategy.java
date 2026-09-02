package fr.softsf.vault.spi;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Optional;

/**
 * Polymorphic strategy interface for OS-native credential store operations using character arrays for keys and boolean confirmations.
 */
public sealed interface VaultStrategy permits MacKeychainStrategy, LinuxKeyringStrategy, WindowsCredentialManagerStrategy {
    System.Logger LOGGER = System.getLogger(VaultStrategy.class.getName());

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

    static VaultStrategy detect() {
        String os = System.getProperty("os.name").toLowerCase(java.util.Locale.ROOT);
        LOGGER.log(System.Logger.Level.DEBUG, "Detecting OS environment: {0}", os);
        return switch (os) {
            case String s when s.contains("win") -> {
                LOGGER.log(System.Logger.Level.INFO, "Selected Windows Credential Manager strategy.");
                yield new WindowsCredentialManagerStrategy();
            }
            case String s when s.contains("mac") -> {
                LOGGER.log(System.Logger.Level.INFO, "Selected macOS Keychain strategy.");
                yield new MacKeychainStrategy();
            }
            case String s when s.contains("nix") || s.contains("nux") -> {
                LOGGER.log(System.Logger.Level.INFO, "Selected Linux Keyring strategy.");
                yield new LinuxKeyringStrategy();
            }
            default -> {
                LOGGER.log(System.Logger.Level.ERROR, "Unsupported operating system detected: {0}", os);
                throw new UnsupportedOperationException("Unsupported operating system: " + os);
            }
        };
    }
}