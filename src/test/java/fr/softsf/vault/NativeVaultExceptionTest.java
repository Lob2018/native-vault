package fr.softsf.vault;

import fr.softsf.vault.exception.NativeVaultException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Unit tests for {@link NativeVaultException}.
 */
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