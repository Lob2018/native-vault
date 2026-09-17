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
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * Linux Keyring implementation of the VaultStrategy interface utilizing the FFM API with proper
 * memory cleanup, safe null-terminated string scanning, and heap memory hygiene.
 *
 * @see <a href="https://gnome.pages.gitlab.gnome.org/libsecret/index.html">Libsecret API
 *     Reference</a>
 * @see <a href="https://docs.gtk.org/glib/">GLib Reference Manual</a>
 */
public final class LinuxKeyringStrategy extends AbstractVaultStrategy {
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

    private final MemorySegment schemaSegment;

    private static final MethodHandle STORE_HANDLE;
    private static final MethodHandle LOOKUP_HANDLE;
    private static final MethodHandle CLEAR_HANDLE;
    private static final MethodHandle G_FREE_HANDLE;
    public static final String KEY = "key";

    static {
        try {
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

    /**
     * Initializes a new instance of the {@code LinuxKeyringStrategy} with a custom namespace.
     *
     * @param schemaName the isolated schema name character array used for the Linux keyring
     * @throws IllegalArgumentException if {@code schemaName} is null or empty
     */
    public LinuxKeyringStrategy(char[] schemaName) {
        if (schemaName == null || schemaName.length == 0) {
            throw new IllegalArgumentException("Schema name cannot be null or empty");
        }
        Arena arena = Arena.ofShared();
        MemorySegment nameSegment = null;
        try {
            nameSegment = allocateSegment(arena, schemaName, StandardCharsets.UTF_8);
            MemorySegment attrNameSegment = arena.allocateFrom(KEY, StandardCharsets.UTF_8);
            MemorySegment segment = arena.allocate(SECRET_SCHEMA_LAYOUT);
            segment.set(
                    ValueLayout.ADDRESS,
                    SECRET_SCHEMA_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("name")),
                    nameSegment);
            segment.set(
                    ValueLayout.JAVA_INT,
                    SECRET_SCHEMA_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("flags")),
                    0);
            long attr0Offset =
                    SECRET_SCHEMA_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement(ATTRIBUTES),
                            MemoryLayout.PathElement.sequenceElement(0));
            segment.set(ValueLayout.ADDRESS, attr0Offset, attrNameSegment);
            segment.set(ValueLayout.JAVA_INT, attr0Offset + ValueLayout.ADDRESS.byteSize(), 0);
            long attr1Offset =
                    SECRET_SCHEMA_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement(ATTRIBUTES),
                            MemoryLayout.PathElement.sequenceElement(1));
            segment.set(ValueLayout.ADDRESS, attr1Offset, MemorySegment.NULL);
            segment.set(ValueLayout.JAVA_INT, attr1Offset + ValueLayout.ADDRESS.byteSize(), 0);
            this.schemaSegment = segment;
        } finally {
            zeroFill(nameSegment);
        }
    }

    @Override
    public boolean store(char[] key, char[] secret) throws NativeVaultException {
        validateKey(key);
        validateSecret(secret);
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment keySeg = null;
            MemorySegment secretSeg = null;
            MemorySegment nativePassword = null;
            try {
                keySeg = allocateSegment(confinedArena, key, StandardCharsets.UTF_8);
                MemorySegment attrKeySeg = confinedArena.allocateFrom(KEY, StandardCharsets.UTF_8);
                MemorySegment labelSeg =
                        confinedArena.allocateFrom("NativeVault Secret", StandardCharsets.UTF_8);
                secretSeg = allocateSegment(confinedArena, secret, StandardCharsets.UTF_8);
                long secretBytesSize = secretSeg.byteSize();
                nativePassword = confinedArena.allocate(secretBytesSize + 1);
                nativePassword.copyFrom(secretSeg);
                nativePassword.set(ValueLayout.JAVA_BYTE, secretBytesSize, (byte) 0);
                return (boolean)
                        STORE_HANDLE.invokeExact(
                                schemaSegment,
                                MemorySegment.NULL,
                                labelSeg,
                                nativePassword,
                                MemorySegment.NULL,
                                MemorySegment.NULL,
                                attrKeySeg,
                                keySeg,
                                MemorySegment.NULL);
            } finally {
                zeroFill(nativePassword);
                zeroFill(secretSeg);
                zeroFill(keySeg);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to store secret in Linux Keyring", t);
        }
    }

    @Override
    public Optional<char[]> retrieve(char[] key) throws NativeVaultException {
        validateKey(key);
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment keySeg = null;
            MemorySegment result = null;
            long passwordLength = 0;
            try {
                keySeg = allocateSegment(confinedArena, key, StandardCharsets.UTF_8);
                MemorySegment attrKeySeg = confinedArena.allocateFrom(KEY, StandardCharsets.UTF_8);
                result =
                        (MemorySegment)
                                LOOKUP_HANDLE.invokeExact(
                                        schemaSegment,
                                        MemorySegment.NULL,
                                        MemorySegment.NULL,
                                        attrKeySeg,
                                        keySeg,
                                        MemorySegment.NULL);
                if (result == null || result.address() == 0 || result.equals(MemorySegment.NULL)) {
                    return Optional.empty();
                }
                MemorySegment boundedResult =
                        result.reinterpret(LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE);
                while (boundedResult.get(ValueLayout.JAVA_BYTE, passwordLength) != 0) {
                    passwordLength++;
                }
                MemorySegment passwordSegment = boundedResult.asSlice(0, passwordLength);
                ByteBuffer byteBuffer = passwordSegment.asByteBuffer();
                CharBuffer charBuffer = StandardCharsets.UTF_8.decode(byteBuffer);
                char[] chars = new char[charBuffer.remaining()];
                charBuffer.get(chars);
                return Optional.of(chars);
            } finally {
                if (result != null && result.address() != 0 && !result.equals(MemorySegment.NULL)) {
                    if (passwordLength > 0) {
                        zeroFill(result.reinterpret(passwordLength));
                    }
                    G_FREE_HANDLE.invokeExact(result);
                }
                zeroFill(keySeg);
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
        validateKey(key);
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment keySeg = null;
            try {
                keySeg = allocateSegment(confinedArena, key, StandardCharsets.UTF_8);
                MemorySegment attrKeySeg = confinedArena.allocateFrom(KEY, StandardCharsets.UTF_8);
                return (boolean)
                        CLEAR_HANDLE.invokeExact(
                                schemaSegment,
                                MemorySegment.NULL,
                                MemorySegment.NULL,
                                attrKeySeg,
                                keySeg,
                                MemorySegment.NULL);
            } finally {
                zeroFill(keySeg);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to delete secret from Linux Keyring", t);
        }
    }

    @Override
    public boolean exists(char[] key) throws NativeVaultException {
        validateKey(key);
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment keySeg = null;
            MemorySegment result = null;
            long passwordLength = 0;
            try {
                keySeg = allocateSegment(confinedArena, key, StandardCharsets.UTF_8);
                MemorySegment attrKeySeg = confinedArena.allocateFrom(KEY, StandardCharsets.UTF_8);
                result =
                        (MemorySegment)
                                LOOKUP_HANDLE.invokeExact(
                                        schemaSegment,
                                        MemorySegment.NULL,
                                        MemorySegment.NULL,
                                        attrKeySeg,
                                        keySeg,
                                        MemorySegment.NULL);
                if (result == null || result.address() == 0 || result.equals(MemorySegment.NULL)) {
                    return false;
                }
                MemorySegment boundedResult =
                        result.reinterpret(LINUX_SECRET_SERVICE_MAX_SECRET_BYTE_SIZE);
                while (boundedResult.get(ValueLayout.JAVA_BYTE, passwordLength) != 0) {
                    passwordLength++;
                }
                return true;
            } finally {
                if (result != null && result.address() != 0 && !result.equals(MemorySegment.NULL)) {
                    if (passwordLength > 0) {
                        zeroFill(result.reinterpret(passwordLength));
                    }
                    G_FREE_HANDLE.invokeExact(result);
                }
                zeroFill(keySeg);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to check secret existence in Linux Keyring", t);
        }
    }
}
