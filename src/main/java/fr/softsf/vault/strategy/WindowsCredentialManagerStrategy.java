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
import java.lang.invoke.VarHandle;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * Windows Credential Manager implementation of the VaultStrategy interface utilizing the FFM API
 * with proper segment reinterpretation, record mapping, and error handling.
 *
 * @see <a href="https://learn.microsoft.com/en-us/windows/win32/api/wincred/">Wincred.h Win32 API
 *     Reference</a>
 */
public final class WindowsCredentialManagerStrategy extends AbstractVaultStrategy {
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

    /** Represents a mapped view of the native Windows CREDENTIAL structure. */
    private record NativeCredentialRecord(
            int flags,
            int type,
            MemorySegment targetName,
            int credentialBlobSize,
            MemorySegment credentialBlob,
            int persist) {

        private static final VarHandle FLAGS_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Flags"));
        private static final VarHandle TYPE_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Type"));
        private static final VarHandle TARGET_NAME_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("TargetName"));
        private static final VarHandle COMMENT_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Comment"));
        private static final VarHandle BLOB_SIZE_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(
                        MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB_SIZE));
        private static final VarHandle BLOB_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB));
        private static final VarHandle PERSIST_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Persist"));
        private static final VarHandle ATTRIBUTE_COUNT_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(
                        MemoryLayout.PathElement.groupElement("AttributeCount"));
        private static final VarHandle ATTRIBUTES_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("Attributes"));
        private static final VarHandle TARGET_ALIAS_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("TargetAlias"));
        private static final VarHandle USER_NAME_HANDLE =
                CREDENTIAL_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("UserName"));

        /**
         * Maps a native memory segment to a NativeCredentialRecord instance.
         *
         * @param segment the memory segment representing the native struct
         * @return the mapped record
         */
        public static NativeCredentialRecord fromSegment(MemorySegment segment) {
            return new NativeCredentialRecord(
                    (int) FLAGS_HANDLE.get(segment, 0L),
                    (int) TYPE_HANDLE.get(segment, 0L),
                    (MemorySegment) TARGET_NAME_HANDLE.get(segment, 0L),
                    (int) BLOB_SIZE_HANDLE.get(segment, 0L),
                    (MemorySegment) BLOB_HANDLE.get(segment, 0L),
                    (int) PERSIST_HANDLE.get(segment, 0L));
        }
    }

    private static final MethodHandle WRITE_HANDLE;
    private static final MethodHandle READ_HANDLE;
    private static final MethodHandle DELETE_HANDLE;
    private static final MethodHandle CRED_FREE_HANDLE;
    private final char[] namespace;

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

    /**
     * Initializes a new instance of the {@code WindowsCredentialManagerStrategy} with a custom
     * namespace.
     *
     * @param namespace the isolated namespace character array used as a TargetName prefix for
     *     Windows credentials
     * @throws IllegalArgumentException if {@code namespace} is null or empty
     */
    public WindowsCredentialManagerStrategy(char[] namespace) {
        if (namespace == null || namespace.length == 0) {
            throw new IllegalArgumentException("Namespace cannot be null or empty");
        }
        this.namespace = namespace.clone();
    }

    @Override
    public boolean store(char[] key, char[] secret) throws NativeVaultException {
        validateKey(key);
        validateSecret(secret);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = null;
            MemorySegment credentialSegment;
            MemorySegment secretSeg = null;
            MemorySegment nativePassword = null;
            char[] namespacedKey = null;
            try {
                namespacedKey = concatNamespaceAndKey(namespace, key);
                targetNameSegment =
                        allocateSegment(arena, namespacedKey, StandardCharsets.UTF_16LE);
                credentialSegment = arena.allocate(CREDENTIAL_LAYOUT);
                NativeCredentialRecord.FLAGS_HANDLE.set(credentialSegment, 0L, 0);
                NativeCredentialRecord.TYPE_HANDLE.set(credentialSegment, 0L, CRED_TYPE_GENERIC);
                NativeCredentialRecord.TARGET_NAME_HANDLE.set(
                        credentialSegment, 0L, targetNameSegment);
                NativeCredentialRecord.COMMENT_HANDLE.set(
                        credentialSegment, 0L, MemorySegment.NULL);
                secretSeg = allocateSegment(arena, secret, StandardCharsets.UTF_16LE);
                long secretBytesSize = secretSeg.byteSize();
                nativePassword = arena.allocate(secretBytesSize);
                nativePassword.copyFrom(secretSeg);
                NativeCredentialRecord.BLOB_SIZE_HANDLE.set(
                        credentialSegment, 0L, (int) secretBytesSize);
                NativeCredentialRecord.BLOB_HANDLE.set(credentialSegment, 0L, nativePassword);
                NativeCredentialRecord.PERSIST_HANDLE.set(
                        credentialSegment, 0L, CRED_PERSIST_LOCAL_MACHINE);
                NativeCredentialRecord.ATTRIBUTE_COUNT_HANDLE.set(credentialSegment, 0L, 0);
                NativeCredentialRecord.ATTRIBUTES_HANDLE.set(
                        credentialSegment, 0L, MemorySegment.NULL);
                NativeCredentialRecord.TARGET_ALIAS_HANDLE.set(
                        credentialSegment, 0L, MemorySegment.NULL);
                NativeCredentialRecord.USER_NAME_HANDLE.set(
                        credentialSegment, 0L, MemorySegment.NULL);
                int status = (int) WRITE_HANDLE.invokeExact(credentialSegment, 0);
                return status != 0;
            } finally {
                zeroFill(nativePassword);
                zeroFill(secretSeg);
                zeroFill(targetNameSegment);
                zeroFill(namespacedKey);
            }
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
        validateKey(key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = null;
            MemorySegment outCredPtr;
            MemorySegment rawCredPtr = null;
            char[] namespacedKey = null;
            try {
                namespacedKey = concatNamespaceAndKey(namespace, key);
                targetNameSegment =
                        allocateSegment(arena, namespacedKey, StandardCharsets.UTF_16LE);
                outCredPtr = arena.allocate(ValueLayout.ADDRESS);
                int status =
                        (int)
                                READ_HANDLE.invokeExact(
                                        targetNameSegment, CRED_TYPE_GENERIC, 0, outCredPtr);
                if (status == 0) {
                    return Optional.empty();
                }
                rawCredPtr = outCredPtr.get(ValueLayout.ADDRESS, 0);
                if (rawCredPtr == null
                        || rawCredPtr.address() == 0
                        || rawCredPtr.equals(MemorySegment.NULL)) {
                    return Optional.empty();
                }
                MemorySegment credStruct = rawCredPtr.reinterpret(CREDENTIAL_LAYOUT.byteSize());
                NativeCredentialRecord credential = NativeCredentialRecord.fromSegment(credStruct);
                int blobSize = credential.credentialBlobSize();
                MemorySegment blobPtr = credential.credentialBlob();
                if (blobPtr == null
                        || blobPtr.address() == 0
                        || blobPtr.equals(MemorySegment.NULL)
                        || blobSize <= 0) {
                    return Optional.empty();
                }
                MemorySegment boundedBlob =
                        blobPtr.reinterpret(WINDOWS_CREDENTIAL_MANAGER_MAX_SECRET_BYTE_SIZE);
                MemorySegment actualBlob = boundedBlob.asSlice(0, blobSize);
                CharBuffer charBuffer = StandardCharsets.UTF_16LE.decode(actualBlob.asByteBuffer());
                char[] chars = new char[charBuffer.remaining()];
                charBuffer.get(chars);
                return Optional.of(chars);
            } finally {
                freeCredential(rawCredPtr);
                zeroFill(targetNameSegment);
                zeroFill(namespacedKey);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException(
                    "Failed to retrieve secret from Windows Credential Manager", t);
        }
    }

    /**
     * Frees the raw credential pointer and zero-fills its internal blob.
     *
     * @param rawCredPtr the raw credential pointer
     * @throws Throwable if a method handle invocation fails
     */
    private void freeCredential(MemorySegment rawCredPtr) throws Throwable {
        if (rawCredPtr == null
                || rawCredPtr.address() == 0
                || rawCredPtr.equals(MemorySegment.NULL)) {
            return;
        }
        MemorySegment credStruct = rawCredPtr.reinterpret(CREDENTIAL_LAYOUT.byteSize());
        NativeCredentialRecord credential = NativeCredentialRecord.fromSegment(credStruct);
        int blobSize = credential.credentialBlobSize();
        MemorySegment blobPtr = credential.credentialBlob();
        if (blobPtr != null
                && blobPtr.address() != 0
                && !blobPtr.equals(MemorySegment.NULL)
                && blobSize > 0) {
            zeroFill(blobPtr.reinterpret(blobSize));
        }
        CRED_FREE_HANDLE.invokeExact(rawCredPtr);
    }

    @Override
    public boolean delete(char[] key) throws NativeVaultException {
        validateKey(key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = null;
            char[] namespacedKey = null;
            try {
                namespacedKey = concatNamespaceAndKey(namespace, key);
                targetNameSegment =
                        allocateSegment(arena, namespacedKey, StandardCharsets.UTF_16LE);
                int status =
                        (int) DELETE_HANDLE.invokeExact(targetNameSegment, CRED_TYPE_GENERIC, 0);
                return status != 0;
            } finally {
                zeroFill(targetNameSegment);
                zeroFill(namespacedKey);
            }
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
        validateKey(key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment targetNameSegment = null;
            MemorySegment outCredPtr;
            MemorySegment rawCredPtr = null;
            char[] namespacedKey = null;
            try {
                namespacedKey = concatNamespaceAndKey(namespace, key);
                targetNameSegment =
                        allocateSegment(arena, namespacedKey, StandardCharsets.UTF_16LE);
                outCredPtr = arena.allocate(ValueLayout.ADDRESS);
                int status =
                        (int)
                                READ_HANDLE.invokeExact(
                                        targetNameSegment, CRED_TYPE_GENERIC, 0, outCredPtr);
                if (status == 0) {
                    return false;
                }
                rawCredPtr = outCredPtr.get(ValueLayout.ADDRESS, 0);
                return rawCredPtr != null
                        && rawCredPtr.address() != 0
                        && !rawCredPtr.equals(MemorySegment.NULL);
            } finally {
                freeCredential(rawCredPtr);
                zeroFill(targetNameSegment);
                zeroFill(namespacedKey);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException(
                    "Failed to check secret existence in Windows Credential Manager", t);
        }
    }
}
