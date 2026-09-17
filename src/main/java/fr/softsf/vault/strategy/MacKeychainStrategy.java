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
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * macOS Keychain implementation of the VaultStrategy interface utilizing the FFM API with proper
 * memory cleanup, namespace isolation, and error handling.
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

    private final char[] namespace;

    static {
        try {
            ADD_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemAdd",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            UPDATE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemUpdate",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            COPY_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemCopyMatching",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            DELETE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemDelete",
                            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
            CF_RELEASE_HANDLE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFRelease",
                            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            throw new ExceptionInInitializerError(t);
        }
    }

    /**
     * Initializes a new instance of the {@code MacKeychainStrategy} with a custom namespace.
     *
     * @param namespace the isolated namespace character array used as a prefix for keychain items
     * @throws IllegalArgumentException if {@code namespace} is null or empty
     */
    public MacKeychainStrategy(char[] namespace) {
        if (namespace == null || namespace.length == 0) {
            throw new IllegalArgumentException("Namespace cannot be null or empty");
        }
        this.namespace = namespace.clone();
    }

    @Override
    public boolean store(char[] key, char[] secret) throws NativeVaultException {
        validateKey(key);
        validateSecret(secret);
        char[] qualifiedKey = null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = null;
            MemorySegment secretSegment = null;
            try {
                qualifiedKey = concatNamespaceAndKey(namespace, key);
                keySegment = allocateSegment(arena, qualifiedKey, StandardCharsets.UTF_8);
                secretSegment = allocateSegment(arena, secret, StandardCharsets.UTF_8);
                int status = (int) ADD_HANDLE.invokeExact(keySegment, secretSegment);
                if (status == -25299) { // errSecDuplicateItem
                    return (int) UPDATE_HANDLE.invokeExact(keySegment, secretSegment) == 0;
                }
                return status == 0;
            } finally {
                zeroFill(secretSegment);
                zeroFill(keySegment);
                zeroFill(qualifiedKey);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to store secret in macOS Keychain", t);
        }
    }

    @Override
    public Optional<char[]> retrieve(char[] key) throws NativeVaultException {
        validateKey(key);
        char[] qualifiedKey = null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment query = null;
            MemorySegment resultData;
            MemorySegment nativePtr = null;
            try {
                qualifiedKey = concatNamespaceAndKey(namespace, key);
                query = allocateSegment(arena, qualifiedKey, StandardCharsets.UTF_8);
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
                MemorySegment boundedPtr =
                        nativePtr.reinterpret(MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE);
                long passwordLength = 0;
                while (boundedPtr.get(ValueLayout.JAVA_BYTE, passwordLength) != 0) {
                    passwordLength++;
                }
                MemorySegment passwordSegment = boundedPtr.asSlice(0, passwordLength);
                CharBuffer charBuffer =
                        StandardCharsets.UTF_8.decode(passwordSegment.asByteBuffer());
                char[] chars = new char[charBuffer.remaining()];
                charBuffer.get(chars);
                return Optional.of(chars);
            } finally {
                freeNativePointer(nativePtr);
                zeroFill(query);
                zeroFill(qualifiedKey);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to retrieve secret from macOS Keychain", t);
        }
    }

    /**
     * Releases the native keychain pointer and securely zero-fills its referenced memory segment.
     *
     * @param nativePtr the native pointer to release
     * @throws Throwable if method handle invocation fails
     */
    private void freeNativePointer(MemorySegment nativePtr) throws Throwable {
        if (nativePtr == null || nativePtr.address() == 0 || nativePtr.equals(MemorySegment.NULL)) {
            return;
        }
        try {
            zeroFill(nativePtr.reinterpret(MACOS_KEYCHAIN_MAX_SECRET_BYTE_SIZE));
        } finally {
            CF_RELEASE_HANDLE.invokeExact(nativePtr);
        }
    }

    @Override
    public boolean delete(char[] key) throws NativeVaultException {
        validateKey(key);
        char[] qualifiedKey = null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySegment = null;
            try {
                qualifiedKey = concatNamespaceAndKey(namespace, key);
                keySegment = allocateSegment(arena, qualifiedKey, StandardCharsets.UTF_8);
                return (int) DELETE_HANDLE.invokeExact(keySegment) == 0;
            } finally {
                zeroFill(keySegment);
                zeroFill(qualifiedKey);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to delete secret from macOS Keychain", t);
        }
    }

    @Override
    public boolean exists(char[] key) throws NativeVaultException {
        validateKey(key);
        char[] qualifiedKey = null;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment query = null;
            MemorySegment resultData;
            MemorySegment nativePtr;
            try {
                qualifiedKey = concatNamespaceAndKey(namespace, key);
                query = allocateSegment(arena, qualifiedKey, StandardCharsets.UTF_8);
                resultData = arena.allocate(ValueLayout.ADDRESS);
                int status = (int) COPY_HANDLE.invokeExact(query, resultData);
                if (status == 0) {
                    nativePtr = resultData.get(ValueLayout.ADDRESS, 0);
                    if (nativePtr != null
                            && nativePtr.address() != 0
                            && !nativePtr.equals(MemorySegment.NULL)) {
                        freeNativePointer(nativePtr);
                        return true;
                    }
                }
                return false;
            } finally {
                zeroFill(query);
                zeroFill(qualifiedKey);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to check secret existence in macOS Keychain", t);
        }
    }
}
