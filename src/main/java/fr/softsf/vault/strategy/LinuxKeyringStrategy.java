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
import java.util.Optional;

import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * Linux Keyring implementation of the VaultStrategy interface utilizing the FFM API with proper
 * memory cleanup and error handling.
 */
final class LinuxKeyringStrategy implements VaultStrategy {
    private static final String LIB_NAME = "libsecret-1.so.0";
    private static final String GLIB_LIB_NAME = "libglib-2.0.so.0";
    private static final MethodHandle STORE_HANDLE;
    private static final MethodHandle LOOKUP_HANDLE;
    private static final MethodHandle CLEAR_HANDLE;
    private static final MethodHandle G_FREE_HANDLE;

    static {
        STORE_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_NAME,
                        "secret_password_store_sync",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_BOOLEAN,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS));
        LOOKUP_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_NAME,
                        "secret_password_lookup_sync",
                        FunctionDescriptor.of(
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS));
        CLEAR_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        LIB_NAME,
                        "secret_password_clear_sync",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_BOOLEAN,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS,
                                ValueLayout.ADDRESS));
        G_FREE_HANDLE =
                CrossPlatformVaultLoader.loadNativeFunction(
                        GLIB_LIB_NAME, "g_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    }

    /** Initializes a new instance of the LinuxKeyringStrategy. */
    LinuxKeyringStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    @Override
    public boolean store(char[] key, MemorySegment secretData, Arena arena) {
        try {
            ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            return (boolean)
                    STORE_HANDLE.invokeExact(
                            MemorySegment.NULL,
                            keySegment,
                            MemorySegment.NULL,
                            keySegment,
                            secretData,
                            MemorySegment.NULL,
                            MemorySegment.NULL);
        } catch (Throwable t) { // NOSONAR
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
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            MemorySegment result =
                    (MemorySegment)
                            LOOKUP_HANDLE.invokeExact(
                                    MemorySegment.NULL,
                                    keySegment,
                                    MemorySegment.NULL,
                                    MemorySegment.NULL);
            if (result.equals(MemorySegment.NULL)) {
                return Optional.empty();
            }
            long stringLen =
                    result.reinterpret(Long.MAX_VALUE)
                            .getString(0, StandardCharsets.UTF_8)
                            .getBytes(StandardCharsets.UTF_8)
                            .length;
            MemorySegment secretCopy = arena.allocate(stringLen);
            secretCopy.copyFrom(result.reinterpret(stringLen).asSlice(0, stringLen));
            G_FREE_HANDLE.invokeExact(result);
            return Optional.of(secretCopy);
        } catch (Throwable t) { // NOSONAR
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
            return (boolean)
                    CLEAR_HANDLE.invokeExact(
                            MemorySegment.NULL,
                            keySegment,
                            MemorySegment.NULL,
                            MemorySegment.NULL,
                            MemorySegment.NULL);
        } catch (Throwable t) { // NOSONAR
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
            MemorySegment keySegment = arena.allocate(byteBuffer.remaining());
            keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
            MemorySegment result =
                    (MemorySegment)
                            LOOKUP_HANDLE.invokeExact(
                                    MemorySegment.NULL,
                                    keySegment,
                                    MemorySegment.NULL,
                                    MemorySegment.NULL);
            if (result.equals(MemorySegment.NULL)) {
                return false;
            }
            G_FREE_HANDLE.invokeExact(result);
            return true;
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            return false;
        }
    }
}
