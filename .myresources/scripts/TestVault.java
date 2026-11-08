///usr/bin/env jbang "$0" "$@" ; exit $?
//JAVA 25+
//JAVA_OPTIONS --enable-native-access=ALL-UNNAMED
//DEPS /home/lob2018/IdeaProjects/native-vault/target/native-vault-0.1.0.jar
//DEPS org.apache.commons:commons-lang3:3.20.0

/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
import fr.softsf.vault.NativeVault;
import fr.softsf.vault.exception.NativeVaultException;
import java.util.Arrays;

/**
 * Test script for verifying NativeVault functionality.
 */
public class TestVault {

    /**
     * Executes the vault test script.
     *
     * @param args command line arguments
     */
    public static void main() {
        char[] namespace = {'f', 'r', '.', 's', 'o', 'f', 't', 's', 'f', '.', 'm', 'y', 'a', 'p', 'p'};
        char[] key = {'u', 'n', 'i', 'q', 'u', 'e', 'k', 'e', 'y'};
        char[] secret = {'m', 'y', '-', 'c', 'r', 'i', 't', 'i', 'c', 'a', 'l', '-', 's', 'e', 'c', 'r', 'e', 't'};
        try {
            NativeVault vault = new NativeVault(namespace);
            boolean stored = vault.setSecret(key, secret);
            System.out.println("Stored: " + stored);// NOSONAR

            boolean exists = vault.hasSecret(key);
            System.out.println("Exists: " + exists);// NOSONAR

            vault.getSecret(key).ifPresent(rawSecret -> {
                try {
                    System.out.println("Retrieved: " + new String(rawSecret));// NOSONAR
                } finally {
                    Arrays.fill(rawSecret, '\0');
                }
            });

            boolean removed = vault.removeSecret(key);
            System.out.println("Removed: " + removed);// NOSONAR
        } catch (NativeVaultException | LinkageError e) {
            System.err.println("Failed to initialize or use native vault: " + e.getMessage());// NOSONAR
        } finally {
            Arrays.fill(namespace, '\0');
            Arrays.fill(key, '\0');
            Arrays.fill(secret, '\0');
        }
    }
}