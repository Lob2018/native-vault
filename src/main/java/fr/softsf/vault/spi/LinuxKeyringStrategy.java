package fr.softsf.vault.spi;

import fr.softsf.vault.internal.CrossPlatformVaultLoader;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Linux Keyring implementation of the VaultStrategy interface utilizing the FFM API with boolean confirmation signatures.
 */
public final class LinuxKeyringStrategy implements VaultStrategy {
    private static final String LIB_NAME = "libsecret-1.so.0";
    private static final MethodHandle STORE_HANDLE;
    private static final MethodHandle LOOKUP_HANDLE;
    private static final MethodHandle CLEAR_HANDLE;

    static {
        STORE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "secret_password_store_sync", FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        LOOKUP_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "secret_password_lookup_sync", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        CLEAR_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "secret_password_clear_sync", FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    }

    /**
     * Initializes a new instance of the LinuxKeyringStrategy.
     */
    public LinuxKeyringStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    @Override
    public boolean store(char[] key, MemorySegment secretData, Arena arena) {
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            return (boolean) STORE_HANDLE.invokeExact(
                    MemorySegment.NULL,
                    keySegment,
                    MemorySegment.NULL,
                    keySegment,
                    secretData,
                    MemorySegment.NULL,
                    MemorySegment.NULL
            );
        } catch (Throwable _) {
            return false;
        }
    }

    @Override
    public Optional<MemorySegment> retrieve(char[] key, Arena arena) {
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            MemorySegment result = (MemorySegment) LOOKUP_HANDLE.invokeExact(
                    MemorySegment.NULL,
                    keySegment,
                    MemorySegment.NULL,
                    MemorySegment.NULL
            );
            if (result.equals(MemorySegment.NULL)) {
                return Optional.empty();
            }
            return Optional.of(result);
        } catch (Throwable _) {
            return Optional.empty();
        }
    }

    @Override
    public boolean delete(char[] key) {
        try (Arena arena = Arena.ofConfined()) {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            return (boolean) CLEAR_HANDLE.invokeExact(
                    MemorySegment.NULL,
                    keySegment,
                    MemorySegment.NULL,
                    MemorySegment.NULL,
                    MemorySegment.NULL
            );
        } catch (Throwable _) {
            return false;
        }
    }

    @Override
    public boolean exists(char[] key) {
        try (Arena arena = Arena.ofConfined()) {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            MemorySegment result = (MemorySegment) LOOKUP_HANDLE.invokeExact(
                    MemorySegment.NULL,
                    keySegment,
                    MemorySegment.NULL,
                    MemorySegment.NULL
            );
            return !result.equals(MemorySegment.NULL);
        } catch (Throwable _) {
            return false;
        }
    }
}