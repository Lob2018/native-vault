/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.GroupLayout;
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
 * Windows Credential Manager implementation of the VaultStrategy interface utilizing the FFM API
 * with proper segment reinterpretation and error handling.
 *
 * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincred/">Wincred.h Win32 API
 *     Reference</a>
 */
final class WindowsCredentialManagerStrategy implements VaultStrategy {
    private static final String LIB_NAME = "Advapi32";
    private static final int CRED_TYPE_GENERIC = 1;
    private static final int CRED_PERSIST_LOCAL_MACHINE = 2;

    public static final String CREDENTIAL_BLOB_SIZE = "CredentialBlobSize";
    public static final String CREDENTIAL_BLOB = "CredentialBlob";
    private static final GroupLayout CREDENTIAL_LAYOUT =
            MemoryLayout.structLayout(
                    ValueLayout.JAVA_INT.withName("Flags"),
                    ValueLayout.JAVA_INT.withName("Type"),
                    ValueLayout.ADDRESS.withName("TargetName"),
                    ValueLayout.ADDRESS.withName("Comment"),
                    MemoryLayout.sequenceLayout(8, ValueLayout.JAVA_BYTE).withName("LastWritten"),
                    ValueLayout.JAVA_INT.withName(CREDENTIAL_BLOB_SIZE),
                    MemoryLayout.paddingLayout(4),
                    ValueLayout.ADDRESS.withName(CREDENTIAL_BLOB),
                    ValueLayout.JAVA_INT.withName("Persist"),
                    ValueLayout.JAVA_INT.withName("AttributeCount"),
                    ValueLayout.ADDRESS.withName("Attributes"),
                    ValueLayout.ADDRESS.withName("TargetAlias"),
                    ValueLayout.ADDRESS.withName("UserName"));

    private static final MethodHandle WRITE_HANDLE;
    private static final MethodHandle READ_HANDLE;
    private static final MethodHandle DELETE_HANDLE;
    private static final MethodHandle CRED_FREE_HANDLE;
    public static final String KEY_CANNOT_BE_NULL_OR_EMPTY = "Key cannot be null or empty";
    public static final String SECRET_DATA_CANNOT_BE_NULL = "SecretData cannot be null";

    static {
        try {
            WRITE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_NAME,
                            "CredWriteW",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_INT));
            READ_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_NAME,
                            "CredReadW",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS));
            DELETE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_NAME,
                            "CredDeleteW",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT));
            CRED_FREE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_NAME, "CredFree", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            throw new ExceptionInInitializerError(t);
        }
    }

    /** Initializes a new instance of the WindowsCredentialManagerStrategy. */
    WindowsCredentialManagerStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    /**
     * Allocates a memory segment for the specified key.
     *
     * @param key the key
     * @param arena the arena
     * @return the memory segment
     */
    private MemorySegment keySegment(char[] key, Arena arena) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        Objects.requireNonNull(arena, "Arena cannot be null");
        ByteBuffer byteBuffer = StandardCharsets.UTF_16LE.encode(CharBuffer.wrap(key));
        MemorySegment keySegment = arena.allocate(byteBuffer.remaining() + 2L);
        keySegment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
        keySegment.set(ValueLayout.JAVA_SHORT, byteBuffer.remaining(), (short) 0);
        byteBuffer.position(0);
        while (byteBuffer.hasRemaining()) {
            byteBuffer.put((byte) 0);
        }
        return keySegment;
    }

    @Override
    public boolean store(char[] key, MemorySegment secretData) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        Objects.requireNonNull(secretData, SECRET_DATA_CANNOT_BE_NULL);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = keySegment(key, arena);
            MemorySegment credentialSegment = arena.allocate(CREDENTIAL_LAYOUT);
            credentialSegment.set(
                    ValueLayout.JAVA_INT,
                    CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Flags")),
                    0);
            credentialSegment.set(
                    ValueLayout.JAVA_INT,
                    CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Type")),
                    CRED_TYPE_GENERIC);
            credentialSegment.set(
                    ValueLayout.ADDRESS,
                    CREDENTIAL_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement("TargetName")),
                    targetNameSegment);
            credentialSegment.set(
                    ValueLayout.ADDRESS,
                    CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Comment")),
                    MemorySegment.NULL);
            long secretBytesSize = secretData.byteSize();
            MemorySegment nativePassword = arena.allocate(secretBytesSize);
            nativePassword.copyFrom(secretData);
            credentialSegment.set(
                    ValueLayout.JAVA_INT,
                    CREDENTIAL_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB_SIZE)),
                    (int) secretBytesSize);
            credentialSegment.set(
                    ValueLayout.ADDRESS,
                    CREDENTIAL_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB)),
                    nativePassword);
            credentialSegment.set(
                    ValueLayout.JAVA_INT,
                    CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Persist")),
                    CRED_PERSIST_LOCAL_MACHINE);
            credentialSegment.set(
                    ValueLayout.JAVA_INT,
                    CREDENTIAL_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement("AttributeCount")),
                    0);
            credentialSegment.set(
                    ValueLayout.ADDRESS,
                    CREDENTIAL_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement("Attributes")),
                    MemorySegment.NULL);
            credentialSegment.set(
                    ValueLayout.ADDRESS,
                    CREDENTIAL_LAYOUT.byteOffset(
                            MemoryLayout.PathElement.groupElement("TargetAlias")),
                    MemorySegment.NULL);
            credentialSegment.set(
                    ValueLayout.ADDRESS,
                    CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("UserName")),
                    MemorySegment.NULL);
            int status = (int) WRITE_HANDLE.invokeExact(credentialSegment, 0);
            return status != 0;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException(
                    "Failed to store secret in Windows Credential Manager", t);
        }
    }

    @Override
    public Optional<char[]> retrieve(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = keySegment(key, arena);
            MemorySegment outCredPtr = arena.allocate(ValueLayout.ADDRESS);
            int status =
                    (int)
                            READ_HANDLE.invokeExact(
                                    targetNameSegment, CRED_TYPE_GENERIC, 0, outCredPtr);
            if (status == 0) {
                return Optional.empty();
            }
            MemorySegment rawCredPtr = outCredPtr.get(ValueLayout.ADDRESS, 0);
            if (rawCredPtr == null
                    || rawCredPtr.address() == 0
                    || rawCredPtr.equals(MemorySegment.NULL)) {
                return Optional.empty();
            }
            MemorySegment credStruct = rawCredPtr.reinterpret(CREDENTIAL_LAYOUT.byteSize());
            int blobSize =
                    credStruct.get(
                            ValueLayout.JAVA_INT,
                            CREDENTIAL_LAYOUT.byteOffset(
                                    MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB_SIZE)));
            MemorySegment blobPtr =
                    credStruct.get(
                            ValueLayout.ADDRESS,
                            CREDENTIAL_LAYOUT.byteOffset(
                                    MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB)));
            if (blobPtr == null
                    || blobPtr.address() == 0
                    || blobPtr.equals(MemorySegment.NULL)
                    || blobSize <= 0) {
                CRED_FREE_HANDLE.invokeExact(rawCredPtr);
                return Optional.empty();
            }
            MemorySegment boundedBlob = blobPtr.reinterpret(blobSize);
            byte[] blobBytes = new byte[blobSize];
            MemorySegment.ofArray(blobBytes).copyFrom(boundedBlob);
            try {
                CharBuffer charBuffer =
                        StandardCharsets.UTF_16LE.decode(ByteBuffer.wrap(blobBytes));
                char[] chars = new char[charBuffer.remaining()];
                charBuffer.get(chars);
                return Optional.of(chars);
            } finally {
                Arrays.fill(blobBytes, (byte) 0);
                CRED_FREE_HANDLE.invokeExact(rawCredPtr);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException(
                    "Failed to retrieve secret from Windows Credential Manager", t);
        }
    }

    @Override
    public boolean delete(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = keySegment(key, arena);
            int status = (int) DELETE_HANDLE.invokeExact(targetNameSegment, CRED_TYPE_GENERIC, 0);
            return status != 0;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException(
                    "Failed to delete secret from Windows Credential Manager", t);
        }
    }

    @Override
    public boolean exists(char[] key) throws NativeVaultException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException(KEY_CANNOT_BE_NULL_OR_EMPTY);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = keySegment(key, arena);
            MemorySegment outCredPtr = arena.allocate(ValueLayout.ADDRESS);
            int status =
                    (int)
                            READ_HANDLE.invokeExact(
                                    targetNameSegment, CRED_TYPE_GENERIC, 0, outCredPtr);
            if (status == 0) {
                return false;
            }
            MemorySegment rawCredPtr = outCredPtr.get(ValueLayout.ADDRESS, 0);
            if (rawCredPtr == null
                    || rawCredPtr.address() == 0
                    || rawCredPtr.equals(MemorySegment.NULL)) {
                return false;
            }
            CRED_FREE_HANDLE.invokeExact(rawCredPtr);
            return true;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException(
                    "Failed to check secret existence in Windows Credential Manager", t);
        }
    }
}
