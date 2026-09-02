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
 * macOS Keychain implementation of the VaultStrategy interface utilizing the FFM API with boolean confirmation signatures.
 */
public final class MacKeychainStrategy implements VaultStrategy {
    private static final String LIB_PATH = "/System/Library/Frameworks/Security.framework/Security"; // NOSONAR
    private static final MethodHandle ADD_HANDLE ;
    private static final MethodHandle UPDATE_HANDLE;
    private static final MethodHandle COPY_HANDLE;
    private static final MethodHandle DELETE_HANDLE;

    static {
        ADD_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemAdd", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        UPDATE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemUpdate", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        COPY_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemCopyMatching", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        DELETE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemDelete", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    }

    /**
     * Initializes a new instance of the MacKeychainStrategy.
     */
    public MacKeychainStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    @Override
    public boolean store(char[] key, MemorySegment secretData, Arena arena) {
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            int status = (int) ADD_HANDLE.invokeExact(keySegment, secretData);
            if (status == -25299) {
                return (int) UPDATE_HANDLE.invokeExact(keySegment, secretData) == 0;
            }
            return status == 0;
        } catch (Throwable _) {
            return false;
        }
    }

    @Override
    public Optional<MemorySegment> retrieve(char[] key, Arena arena) {
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment query = arena.allocate(byteBuffer.remaining());
            query.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            MemorySegment resultData = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) COPY_HANDLE.invokeExact(query, resultData);
            if (status == 0) {
                return Optional.of(resultData.get(ValueLayout.ADDRESS, 0));
            }
            return Optional.empty();
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
            return (int) DELETE_HANDLE.invokeExact(keySegment) == 0;
        } catch (Throwable _) {
            return false;
        }
    }

    @Override
    public boolean exists(char[] key) {
        try (Arena arena = Arena.ofConfined()) {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment query = arena.allocate(byteBuffer.remaining());
            query.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            MemorySegment resultData = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) COPY_HANDLE.invokeExact(query, resultData);
            return status == 0;
        } catch (Throwable _) {
            return false;
        }
    }
}