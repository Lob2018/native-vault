package fr.softsf.vault.strategy;

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
 * macOS Keychain implementation of the VaultStrategy interface utilizing the FFM API with proper memory cleanup and error handling.
 */
final class MacKeychainStrategy implements VaultStrategy {
    private static final String LIB_PATH = "/System/Library/Frameworks/Security.framework/Security"; // NOSONAR
    private static final String CF_LIB_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"; // NOSONAR
    private static final MethodHandle ADD_HANDLE;
    private static final MethodHandle UPDATE_HANDLE;
    private static final MethodHandle COPY_HANDLE;
    private static final MethodHandle DELETE_HANDLE;
    private static final MethodHandle CF_RELEASE_HANDLE;

    static {
        ADD_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemAdd", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        UPDATE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemUpdate", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        COPY_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemCopyMatching", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        DELETE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_PATH, "SecItemDelete", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        CF_RELEASE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(CF_LIB_PATH, "CFRelease", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    /**
     * Initializes a new instance of the MacKeychainStrategy.
     */
    MacKeychainStrategy() {
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
        } catch (Throwable t) { //NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
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
            if (status != 0) {
                return Optional.empty();
            }
            MemorySegment nativePtr = resultData.get(ValueLayout.ADDRESS, 0);
            if (nativePtr.equals(MemorySegment.NULL)) {
                return Optional.empty();
            }
            long size = nativePtr.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8).length;
            MemorySegment secretCopy = arena.allocate(size);
            secretCopy.copyFrom(nativePtr.reinterpret(size).asSlice(0, size));
            CF_RELEASE_HANDLE.invokeExact(nativePtr);
            return Optional.of(secretCopy);
        } catch (Throwable t) { //NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
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
        } catch (Throwable t) { //NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
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
            if (status == 0) {
                MemorySegment nativePtr = resultData.get(ValueLayout.ADDRESS, 0);
                if (!nativePtr.equals(MemorySegment.NULL)) {
                    CF_RELEASE_HANDLE.invokeExact(nativePtr);
                    return true;
                }
            }
            return false;
        } catch (Throwable t) { //NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            return false;
        }
    }
}