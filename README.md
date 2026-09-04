# NativeVault

Unified Java interface for secure credential storage backed by native operating system managers.

Powered by the Foreign Function & Memory (FFM) API (**Project Panama**), this library provides a **zero-JNI/JNA** solution featuring strict memory hygiene (`char[]` sanitation via `Arrays.fill`). It is conceptually inspired by [Microsoft's credential-secure-storage-for-java](https://github.com/microsoft/credential-secure-storage-for-java).

# What this library provides

### Available Secure Storage Providers:

| Secret Type / Operation | Windows (Credential Manager) | Linux (GNOME Keyring / Libsecret) | macOS (Keychain) |
| --- | --- | --- | --- |
| Key-Value Credentials (`char[]` or `String`) | Yes | Yes | Yes |
# How to use this library

Maven is the preferred way to reference this library.

```xml
<dependency>
    <groupId>fr.softsf</groupId>
    <artifactId>native-vault</artifactId>
    <version>1.0.0</version>
</dependency>
```

Here is sample code showing how to use the vault:

```java
// Check if the native vault is operational on the current platform before proceeding
if (NativeVault.isUsable()) {
    try (NativeVault vault = new NativeVault()) {
        // Write action: returns true if successfully stored, false otherwise
        boolean stored = vault.setSecret("my-unique-identifier", "my-critical-secret");
        // Existence check action: returns true if the secret exists, false otherwise
        boolean exists = vault.hasSecret("my-unique-identifier");
        // Read action: returns Optional<char[]>
        vault.getSecret("my-unique-identifier").ifPresent(secret -> {
            // Process secret...
            java.util.Arrays.fill(secret, '\0'); // Mandatory memory cleanup
        });
        // Deletion action: returns true if successfully removed, false otherwise
        boolean removed = vault.removeSecret("my-unique-identifier");
    }
} else {
    // Handle platform unavailability
    System.err.println("Native vault is not operational on this platform.");
}
```

# How to build

1. JDK 22+ (required for the FFM API)
2. Maven 3.8+
3. `mvn clean verify`

# License

This project is licensed under the terms of the GNU General Public License v3.0 (GPLv3).
See the [LICENSE](LICENSE) file for details.
See the [NOTICE.txt](NOTICE.txt) file for required notices and attributions.