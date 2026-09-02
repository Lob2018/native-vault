package fr.softsf.vault.spi;

import fr.softsf.vault.internal.CrossPlatformVaultLoader;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.GroupLayout;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Windows Credential Manager implementation of the VaultStrategy interface utilizing the FFM API with proper segment reinterpretation.
 */
public final class WindowsCredentialManagerStrategy implements VaultStrategy {
    private static final System.Logger LOGGER = System.getLogger(WindowsCredentialManagerStrategy.class.getName());
    private static final String LIB_NAME = "Advapi32";
    private static final int CRED_TYPE_GENERIC = 1;
    private static final int CRED_PERSIST_LOCAL_MACHINE = 2;

    public static final String CREDENTIAL_BLOB_SIZE = "CredentialBlobSize";
    public static final String CREDENTIAL_BLOB = "CredentialBlob";
    private static final GroupLayout CREDENTIAL_LAYOUT = MemoryLayout.structLayout(
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
            ValueLayout.ADDRESS.withName("UserName")
    );

    private static final MethodHandle WRITE_HANDLE;
    private static final MethodHandle READ_HANDLE;
    private static final MethodHandle DELETE_HANDLE;
    private static final MethodHandle CRED_FREE_HANDLE;
    private static final MethodHandle GET_LAST_ERROR_HANDLE;

    static {
        WRITE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "CredWriteW", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
        READ_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "CredReadW", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        DELETE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "CredDeleteW", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
        CRED_FREE_HANDLE = CrossPlatformVaultLoader.loadNativeFunction(LIB_NAME, "CredFree", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        GET_LAST_ERROR_HANDLE = CrossPlatformVaultLoader.loadNativeFunction("Kernel32", "GetLastError", FunctionDescriptor.of(ValueLayout.JAVA_INT));
    }

    /**
     * Initializes a new instance of the WindowsCredentialManagerStrategy.
     */
    public WindowsCredentialManagerStrategy() {
        // Stateless implementation; native method handles are loaded statically.
    }

    @Override
    public boolean store(char[] key, MemorySegment secretData, Arena arena) {
        try {
            String keyStr = new String(key) + "\0";
            MemorySegment targetNameSegment = arena.allocateFrom(keyStr, StandardCharsets.UTF_16LE);
            MemorySegment credentialSegment = arena.allocate(CREDENTIAL_LAYOUT);
            credentialSegment.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Flags")), 0);
            credentialSegment.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Type")), CRED_TYPE_GENERIC);
            credentialSegment.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("TargetName")), targetNameSegment);
            credentialSegment.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Comment")), MemorySegment.NULL);
            credentialSegment.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB_SIZE)), (int) secretData.byteSize());
            credentialSegment.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB)), secretData);
            credentialSegment.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Persist")), CRED_PERSIST_LOCAL_MACHINE);
            credentialSegment.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("AttributeCount")), 0);
            credentialSegment.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Attributes")), MemorySegment.NULL);
            credentialSegment.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("TargetAlias")), MemorySegment.NULL);
            credentialSegment.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("UserName")), MemorySegment.NULL);
            int status = (int) WRITE_HANDLE.invokeExact(credentialSegment, 0);
            if (status == 0) {
                int errorCode = (int) GET_LAST_ERROR_HANDLE.invokeExact();
                LOGGER.log(System.Logger.Level.ERROR, "CredWriteW failed with error code: {0}", errorCode);
            }
            return status != 0;
        } catch (Throwable t) {//NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            LOGGER.log(System.Logger.Level.ERROR, "Exception during store: {0}", t.getMessage(), t);
            return false;
        }
    }

    @Override
    public Optional<MemorySegment> retrieve(char[] key, Arena arena) {
        try {
            String keyStr = new String(key) + "\0";
            MemorySegment targetNameSegment = arena.allocateFrom(keyStr, StandardCharsets.UTF_16LE);
            MemorySegment outCredPtr = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) READ_HANDLE.invokeExact(targetNameSegment, CRED_TYPE_GENERIC, 0, outCredPtr);
            if (status != 0) {
                MemorySegment rawCredPtr = outCredPtr.get(ValueLayout.ADDRESS, 0);
                MemorySegment credStruct = rawCredPtr.reinterpret(CREDENTIAL_LAYOUT.byteSize());
                int blobSize = credStruct.get(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB_SIZE)));
                MemorySegment blobPtr = credStruct.get(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement(CREDENTIAL_BLOB)));
                MemorySegment secretCopy = arena.allocate(blobSize);
                secretCopy.copyFrom(blobPtr.reinterpret(blobSize).asSlice(0, blobSize));
                CRED_FREE_HANDLE.invokeExact(rawCredPtr);
                return Optional.of(secretCopy);
            }
            return Optional.empty();
        } catch (Throwable t) {//NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            LOGGER.log(System.Logger.Level.ERROR, "Exception during retrieve: {0}", t.getMessage(), t);
            return Optional.empty();
        }
    }

    @Override
    public boolean delete(char[] key) {
        try (Arena arena = Arena.ofConfined()) {
            String keyStr = new String(key) + "\0";
            MemorySegment targetNameSegment = arena.allocateFrom(keyStr, StandardCharsets.UTF_16LE);
            int status = (int) DELETE_HANDLE.invokeExact(targetNameSegment, CRED_TYPE_GENERIC, 0);
            return status != 0;
        } catch (Throwable t) {//NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            LOGGER.log(System.Logger.Level.ERROR, "Exception during delete: {0}", t.getMessage(), t);
            return false;
        }
    }

    @Override
    public boolean exists(char[] key) {
        try (Arena arena = Arena.ofConfined()) {
            String keyStr = new String(key) + "\0";
            MemorySegment targetNameSegment = arena.allocateFrom(keyStr, StandardCharsets.UTF_16LE);
            MemorySegment outCredPtr = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) READ_HANDLE.invokeExact(targetNameSegment, CRED_TYPE_GENERIC, 0, outCredPtr);
            if (status != 0) {
                MemorySegment rawCredPtr = outCredPtr.get(ValueLayout.ADDRESS, 0);
                CRED_FREE_HANDLE.invokeExact(rawCredPtr);
                return true;
            }
            return false;
        } catch (Throwable t) {//NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            LOGGER.log(System.Logger.Level.ERROR, "Exception during exists check: {0}", t.getMessage(), t);
            return false;
        }
    }
}