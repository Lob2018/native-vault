/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * Linux Keyring implementation of the VaultStrategy interface utilizing the FFM API with proper
 * memory cleanup and error handling.
 *
 * @see <a href="https://gnome.pages.gitlab.gnome.org/libsecret/index.html">Libsecret API
 *     Reference</a>
 * @see <a href="https://docs.gtk.org/glib/">GLib Reference Manual</a>
 */
final class LinuxKeyringStrategy implements VaultStrategy {
    private static final String LIB_NAME = "libsecret-1.so.0";
    private static final String GLIB_LIB_NAME = "libglib-2.0.so.0";
    private static final MemoryLayout SECRET_SCHEMA_ATTRIBUTE_LAYOUT =
            MemoryLayout.structLayout(
                    ValueLayout.ADDRESS.withName("name"),
                    ValueLayout.JAVA_INT.withName("type"),
                    MemoryLayout.paddingLayout(4));
    public static final String ATTRIBUTES = "attributes";
    private static final MemoryLayout SECRET_SCHEMA_LAYOUT =
            MemoryLayout.structLayout(
                    ValueLayout.ADDRESS.withName("name"),
                    ValueLayout.JAVA_INT.withName("flags"),
                    MemoryLayout.paddingLayout(4),
                    MemoryLayout.sequenceLayout(32, SECRET_SCHEMA_ATTRIBUTE_LAYOUT)
                            .withName(ATTRIBUTES),
                    MemoryLayout.sequenceLayout(7, ValueLayout.ADDRESS).withName("reserved"));
    private static final MemorySegment SCHEMA_SEGMENT;
    private static final MethodHandle STORE_HANDLE;
    private static final MethodHandle LOOKUP_HANDLE;
    private static final MethodHandle CLEAR_HANDLE;
    private static final MethodHandle G_FREE_HANDLE;
    public static final String ARENA_CANNOT_BE_NULL = "Arena cannot be null";
    public static final String KEY_CANNOT_BE_NULL_OR_EMPTY = "Key cannot be null or empty";

    public static final String KEY = "key";

    static {
        try {
            Arena arena = Arena.global();
            MemorySegment nameSegment =
                    arena.allocateFrom("fr.softsf.vault", StandardCharsets.UTF_8);
            MemorySegment attrNameSegment = arena.allocateFrom(KEY, StandardCharsets.UTF_8);
            SCHEMA_SEGMENT = arena.allocate(SECRET_SCHEMA_LAYOUT);
            SCHEMA_SEGMENT.set(
                    ValueLayout.ADDRESS,
                    SECRET_SCHEMA_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("name")),
                    nameSegment);
            SCHEMA_SEGMENT.set(
                    ValueLayout.JAVA_INT,
                    SECRET_SCHEMA_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("flags")),
                    0);
            long attr0Offset =
                    SECRET_SCHEMA_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement(ATTRIBUTES),
                            MemoryLayout.PathElement.sequenceElement(0));
            SCHEMA_SEGMENT.set(ValueLayout.ADDRESS, attr0Offset, attrNameSegment);
            SCHEMA_SEGMENT.set(
                    ValueLayout.JAVA_INT, attr0Offset + ValueLayout.ADDRESS.byteSize(), 0);
            long attr1Offset =
                    SECRET_SCHEMA_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement(ATTRIBUTES),
                            MemoryLayout.PathElement.sequenceElement(1));
            SCHEMA_SEGMENT.set(ValueLayout.ADDRESS, attr1Offset, MemorySegment.NULL);
            SCHEMA_SEGMENT.set(
                    ValueLayout.JAVA_INT, attr1Offset + ValueLayout.ADDRESS.byteSize(), 0);
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
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            G_FREE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            GLIB_LIB_NAME,
                            "g_free",
                            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            throw new ExceptionInInitializerError(t);
        }
    }

    /** Initializes a new instance of the LinuxKeyringStrategy. */
    LinuxKeyringStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    /**
     * Allocates and populates a memory segment for the given key using the provided arena.
     *
     * @param key the key characters
     * @param arena the memory arena
     * @return the allocated memory segment containing the encoded key
     */
    private MemorySegment keySegment(char[] key, Arena arena) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        Objects.requireNonNull(arena, ARENA_CANNOT_BE_NULL);
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(key));
        MemorySegment keySeg = arena.allocate(byteBuffer.remaining());
        keySeg.copyFrom(MemorySegment.ofBuffer(byteBuffer));
        byteBuffer.position(0);
        while (byteBuffer.hasRemaining()) {
            byteBuffer.put((byte) 0);
        }
        return keySeg;
    }

    @Override
    public boolean store(char[] key, MemorySegment secretData) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        Objects.requireNonNull(secretData, "SecretData cannot be null");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = keySegment(key, arena);
            MemorySegment attrKeySeg = arena.allocateFrom(KEY, StandardCharsets.UTF_8);
            MemorySegment labelSeg =
                    arena.allocateFrom("NativeVault Secret", StandardCharsets.UTF_8);
            long secretBytesSize = secretData.byteSize();
            MemorySegment nativePassword = arena.allocate(secretBytesSize);
            nativePassword.copyFrom(secretData);
            return (boolean)
                    STORE_HANDLE.invokeExact(
                            SCHEMA_SEGMENT,
                            MemorySegment.NULL,
                            labelSeg,
                            nativePassword,
                            MemorySegment.NULL,
                            MemorySegment.NULL,
                            attrKeySeg,
                            keySeg,
                            MemorySegment.NULL);
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to store secret in Linux Keyring", t);
        }
    }

    @Override
    public Optional<char[]> retrieve(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = keySegment(key, arena);
            MemorySegment attrKeySeg = arena.allocateFrom(KEY, StandardCharsets.UTF_8);
            MemorySegment result =
                    (MemorySegment)
                            LOOKUP_HANDLE.invokeExact(
                                    SCHEMA_SEGMENT,
                                    MemorySegment.NULL,
                                    MemorySegment.NULL,
                                    attrKeySeg,
                                    keySeg,
                                    MemorySegment.NULL);
            if (result == null || result.address() == 0 || result.equals(MemorySegment.NULL)) {
                return Optional.empty();
            }
            MemorySegment boundedResult = result.reinterpret(Long.MAX_VALUE);
            String password = boundedResult.getString(0, StandardCharsets.UTF_8);
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
            try {
                CharBuffer charBuffer =
                        StandardCharsets.UTF_8.decode(ByteBuffer.wrap(passwordBytes));
                char[] chars = new char[charBuffer.remaining()];
                charBuffer.get(chars);
                return Optional.of(chars);
            } finally {
                Arrays.fill(passwordBytes, (byte) 0);
                G_FREE_HANDLE.invokeExact(result);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to retrieve secret from Linux Keyring", t);
        }
    }

    @Override
    public boolean delete(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = keySegment(key, arena);
            MemorySegment attrKeySeg = arena.allocateFrom(KEY, StandardCharsets.UTF_8);
            return (boolean)
                    CLEAR_HANDLE.invokeExact(
                            SCHEMA_SEGMENT,
                            MemorySegment.NULL,
                            MemorySegment.NULL,
                            attrKeySeg,
                            keySeg,
                            MemorySegment.NULL);
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to delete secret from Linux Keyring", t);
        }
    }

    @Override
    public boolean exists(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = keySegment(key, arena);
            MemorySegment attrKeySeg = arena.allocateFrom(KEY, StandardCharsets.UTF_8);
            MemorySegment result =
                    (MemorySegment)
                            LOOKUP_HANDLE.invokeExact(
                                    SCHEMA_SEGMENT,
                                    MemorySegment.NULL,
                                    MemorySegment.NULL,
                                    attrKeySeg,
                                    keySeg,
                                    MemorySegment.NULL);
            if (result == null || result.address() == 0 || result.equals(MemorySegment.NULL)) {
                return false;
            }
            G_FREE_HANDLE.invokeExact(result);
            return true;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to check secret existence in Linux Keyring", t);
        }
    }
}
