/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * macOS Keychain implementation of the VaultStrategy interface utilizing the FFM API with proper
 * memory cleanup and error handling.
 */
public final class MacKeychainStrategy extends AbstractVaultStrategy {
    private static final String LIB_PATH =
            "/System/Library/Frameworks/Security.framework/Security"; // NOSONAR
    private static final String CF_LIB_PATH =
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"; // NOSONAR
    private static final MethodHandle ADD_HANDLE;
    private static final MethodHandle UPDATE_HANDLE;
    private static final MethodHandle COPY_HANDLE;
    private static final MethodHandle DELETE_HANDLE;
    private static final MethodHandle CF_RELEASE_HANDLE;

    static {
        ADD_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_PATH,
                        "SecItemAdd",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        UPDATE_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_PATH,
                        "SecItemUpdate",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        COPY_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_PATH,
                        "SecItemCopyMatching",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        DELETE_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_PATH,
                        "SecItemDelete",
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        CF_RELEASE_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        CF_LIB_PATH, "CFRelease", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    /** Initializes a new instance of the MacKeychainStrategy. */
    public MacKeychainStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    @Override
    public boolean store(char[] key, char[] secret) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = null;
            MemorySegment secretSegment = null;
            try {
                ByteBuffer keyBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
                keySegment = arena.allocate(keyBuffer.remaining());
                keySegment.copyFrom(MemorySegment.ofBuffer(keyBuffer));
                keyBuffer.position(0);
                while (keyBuffer.hasRemaining()) {
                    keyBuffer.put((byte) 0);
                }

                ByteBuffer secretBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(secret));
                secretSegment = arena.allocate(secretBuffer.remaining());
                secretSegment.copyFrom(MemorySegment.ofBuffer(secretBuffer));
                secretBuffer.position(0);
                while (secretBuffer.hasRemaining()) {
                    secretBuffer.put((byte) 0);
                }

                int status = (int) ADD_HANDLE.invokeExact(keySegment, secretSegment);
                if (status == -25299) {
                    return (int) UPDATE_HANDLE.invokeExact(keySegment, secretSegment) == 0;
                }
                return status == 0;
            } finally {
                zeroFill(secretSegment);
                zeroFill(keySegment);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            return false;
        }
    }

    /**
     * Retrieves a secret associated with the specified key from the keychain.
     *
     * @param key the key identifying the secret
     * @return an Optional containing the secret character array if found, or empty otherwise
     */
    @Override
    public Optional<char[]> retrieve(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment query = null;
            MemorySegment resultData;
            MemorySegment nativePtr = null;
            MemorySegment secretCopy = null;
            byte[] passwordBytes = null;
            try {
                ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
                query = arena.allocate(byteBuffer.remaining());
                query.copyFrom(MemorySegment.ofBuffer(byteBuffer));
                byteBuffer.position(0);
                while (byteBuffer.hasRemaining()) {
                    byteBuffer.put((byte) 0);
                }

                resultData = arena.allocate(ValueLayout.ADDRESS);
                int status = (int) COPY_HANDLE.invokeExact(query, resultData);
                if (status != 0) {
                    return Optional.empty();
                }
                nativePtr = resultData.get(ValueLayout.ADDRESS, 0);
                if (nativePtr == null
                        || nativePtr.address() == 0
                        || nativePtr.equals(MemorySegment.NULL)) {
                    return Optional.empty();
                }
                long size =
                        nativePtr
                                .reinterpret(Long.MAX_VALUE)
                                .getString(0, StandardCharsets.UTF_8)
                                .getBytes(StandardCharsets.UTF_8)
                                .length;
                secretCopy = arena.allocate(size);
                secretCopy.copyFrom(nativePtr.reinterpret(size).asSlice(0, size));

                passwordBytes = new byte[(int) size];
                secretCopy.asByteBuffer().get(passwordBytes);

                CharBuffer charBuffer =
                        StandardCharsets.UTF_8.decode(ByteBuffer.wrap(passwordBytes));
                char[] chars = new char[charBuffer.remaining()];
                charBuffer.get(chars);
                return Optional.of(chars);
            } finally {
                freeNativePointer(nativePtr, secretCopy);
                zeroFill(secretCopy);
                zeroFill(query);
                if (passwordBytes != null) {
                    Arrays.fill(passwordBytes, (byte) 0);
                }
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            return Optional.empty();
        }
    }

    /**
     * Releases the native pointer and zero-fills its referenced memory segment.
     *
     * @param nativePtr the native pointer to release
     * @param secretCopy the segment containing the copied secret data
     * @throws Throwable if method handle invocation fails
     */
    private void freeNativePointer(MemorySegment nativePtr, MemorySegment secretCopy)
            throws Throwable {
        if (nativePtr == null || nativePtr.address() == 0 || nativePtr.equals(MemorySegment.NULL)) {
            return;
        }
        long size = secretCopy != null ? secretCopy.byteSize() : 0;
        if (size > 0) {
            zeroFill(nativePtr.reinterpret(size));
        }
        CF_RELEASE_HANDLE.invokeExact(nativePtr);
    }

    @Override
    public boolean delete(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = null;
            try {
                ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
                keySegment = arena.allocate(byteBuffer.remaining());
                keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
                byteBuffer.position(0);
                while (byteBuffer.hasRemaining()) {
                    byteBuffer.put((byte) 0);
                }
                return (int) DELETE_HANDLE.invokeExact(keySegment) == 0;
            } finally {
                zeroFill(keySegment);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            return false;
        }
    }

    @Override
    public boolean exists(char[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment query = null;
            MemorySegment resultData;
            MemorySegment nativePtr;
            try {
                ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
                query = arena.allocate(byteBuffer.remaining());
                query.copyFrom(MemorySegment.ofBuffer(byteBuffer));
                byteBuffer.position(0);
                while (byteBuffer.hasRemaining()) {
                    byteBuffer.put((byte) 0);
                }
                resultData = arena.allocate(ValueLayout.ADDRESS);
                int status = (int) COPY_HANDLE.invokeExact(query, resultData);
                if (status == 0) {
                    nativePtr = resultData.get(ValueLayout.ADDRESS, 0);
                    if (nativePtr != null
                            && nativePtr.address() != 0
                            && !nativePtr.equals(MemorySegment.NULL)) {
                        long size =
                                nativePtr
                                        .reinterpret(Long.MAX_VALUE)
                                        .getString(0, StandardCharsets.UTF_8)
                                        .getBytes(StandardCharsets.UTF_8)
                                        .length;
                        if (size > 0) {
                            zeroFill(nativePtr.reinterpret(size));
                        }
                        CF_RELEASE_HANDLE.invokeExact(nativePtr);
                        return true;
                    }
                }
                return false;
            } finally {
                zeroFill(query);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            return false;
        }
    }
}
