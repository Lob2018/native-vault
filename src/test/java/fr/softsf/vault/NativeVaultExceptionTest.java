/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault;

import org.junit.jupiter.api.Test;

import fr.softsf.vault.exception.NativeVaultException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/** Unit tests for {@link NativeVaultException}. */
class NativeVaultExceptionTest {

    @Test
    void testExceptionConstructorAndProperties() {
        String expectedMessage = "Test exception message";
        Throwable expectedCause = new RuntimeException("Root cause");
        NativeVaultException exception = new NativeVaultException(expectedMessage, expectedCause);
        assertNotNull(exception);
        assertEquals(expectedMessage, exception.getMessage());
        assertSame(expectedCause, exception.getCause());
    }
}
