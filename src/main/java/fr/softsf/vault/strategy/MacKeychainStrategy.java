/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/** macOS Keychain implementation utilizing FFM API with proper CoreFoundation dictionaries. */
public final class MacKeychainStrategy extends AbstractVaultStrategy {
    private static final String LIB_PATH =
            "/System/Library/Frameworks/Security.framework/Security"; // NOSONAR
    private static final String CF_LIB_PATH =
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"; // NOSONAR

    private static final MethodHandle SEC_ITEM_ADD;
    private static final MethodHandle SEC_ITEM_UPDATE;
    private static final MethodHandle SEC_ITEM_COPY_MATCHING;
    private static final MethodHandle SEC_ITEM_DELETE;

    private static final MethodHandle CF_STRING_CREATE_WITH_C_STRING;
    private static final MethodHandle CF_DATA_CREATE;
    private static final MethodHandle CF_DICTIONARY_CREATE;
    private static final MethodHandle CF_DATA_GET_BYTE_PTR;
    private static final MethodHandle CF_DATA_GET_LENGTH;
    private static final MethodHandle CF_RELEASE;

    private static final MemorySegment K_SEC_CLASS;
    private static final MemorySegment K_SEC_CLASS_GENERIC_PASSWORD;
    private static final MemorySegment K_SEC_ATTR_ACCOUNT;
    private static final MemorySegment K_SEC_VALUE_DATA;
    private static final MemorySegment K_SEC_RETURN_DATA;
    private static final MemorySegment K_SEC_MATCH_LIMIT;
    private static final MemorySegment K_SEC_MATCH_LIMIT_ONE;
    private static final MemorySegment K_CF_BOOLEAN_TRUE;
    private static final MemorySegment K_CF_TYPE_DICTIONARY_KEY_CALLBACKS;
    private static final MemorySegment K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS;

    private final char[] namespace;

    static {
        try {
            SEC_ITEM_ADD =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemAdd",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            SEC_ITEM_UPDATE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemUpdate",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            SEC_ITEM_COPY_MATCHING =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemCopyMatching",
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            SEC_ITEM_DELETE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            LIB_PATH,
                            "SecItemDelete",
                            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

            CF_STRING_CREATE_WITH_C_STRING =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFStringCreateWithCString",
                            FunctionDescriptor.of(
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_INT));
            CF_DATA_CREATE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFDataCreate",
                            FunctionDescriptor.of(
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG));
            CF_DICTIONARY_CREATE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFDictionaryCreate",
                            FunctionDescriptor.of(
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS));
            CF_DATA_GET_BYTE_PTR =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFDataGetBytePtr",
                            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));
            CF_DATA_GET_LENGTH =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFDataGetLength",
                            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
            CF_RELEASE =
                    CrossPlatformVaultLoader.loadNativeFunction(
                            CF_LIB_PATH,
                            "CFRelease",
                            FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

            SymbolLookup secLookup = SymbolLookup.libraryLookup(LIB_PATH, Arena.global());
            SymbolLookup cfudLookup = SymbolLookup.libraryLookup(CF_LIB_PATH, Arena.global());

            K_SEC_CLASS =
                    secLookup
                            .find("kSecClass")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_SEC_CLASS_GENERIC_PASSWORD =
                    secLookup
                            .find("kSecClassGenericPassword")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_SEC_ATTR_ACCOUNT =
                    secLookup
                            .find("kSecAttrAccount")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_SEC_VALUE_DATA =
                    secLookup
                            .find("kSecValueData")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_SEC_RETURN_DATA =
                    secLookup
                            .find("kSecReturnData")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_SEC_MATCH_LIMIT =
                    secLookup
                            .find("kSecMatchLimit")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_SEC_MATCH_LIMIT_ONE =
                    secLookup
                            .find("kSecMatchLimitOne")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_CF_BOOLEAN_TRUE =
                    cfudLookup
                            .find("kCFBooleanTrue")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_CF_TYPE_DICTIONARY_KEY_CALLBACKS =
                    cfudLookup
                            .find("kCFTypeDictionaryKeyCallBacks")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
            K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS =
                    cfudLookup
                            .find("kCFTypeDictionaryValueCallBacks")
                            .orElseThrow()
                            .reinterpret(8)
                            .get(ValueLayout.ADDRESS, 0);
        } catch (Throwable t) { // NOSONAR
            if (t instanceof Error error) {
                throw error;
            }
            throw new ExceptionInInitializerError(t);
        }
    }

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
        char[] qualifiedKey = concatNamespaceAndKey(namespace, key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keyStr = createCFString(arena, qualifiedKey);
            MemorySegment dataVal = createCFData(arena, secret);

            MemorySegment keysArray = arena.allocate(ValueLayout.ADDRESS, 3);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 1, K_SEC_ATTR_ACCOUNT);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 2, K_SEC_VALUE_DATA);

            MemorySegment valuesArray = arena.allocate(ValueLayout.ADDRESS, 3);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS_GENERIC_PASSWORD);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 1, keyStr);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 2, dataVal);

            MemorySegment dict =
                    (MemorySegment)
                            CF_DICTIONARY_CREATE.invokeExact(
                                    MemorySegment.NULL,
                                    keysArray,
                                    valuesArray,
                                    3L,
                                    K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                                    K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);

            int status = (int) SEC_ITEM_ADD.invokeExact(dict, MemorySegment.NULL);
            if (status == -25299) { // errSecDuplicateItem
                MemorySegment updateQueryKeys = arena.allocate(ValueLayout.ADDRESS, 2);
                updateQueryKeys.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS);
                updateQueryKeys.setAtIndex(ValueLayout.ADDRESS, 1, K_SEC_ATTR_ACCOUNT);

                MemorySegment updateQueryVals = arena.allocate(ValueLayout.ADDRESS, 2);
                updateQueryVals.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS_GENERIC_PASSWORD);
                updateQueryVals.setAtIndex(ValueLayout.ADDRESS, 1, keyStr);

                MemorySegment queryDict =
                        (MemorySegment)
                                CF_DICTIONARY_CREATE.invokeExact(
                                        MemorySegment.NULL,
                                        updateQueryKeys,
                                        updateQueryVals,
                                        2L,
                                        K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                                        K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);

                MemorySegment updateKeys = arena.allocate(ValueLayout.ADDRESS, 1);
                updateKeys.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_VALUE_DATA);

                MemorySegment updateVals = arena.allocate(ValueLayout.ADDRESS, 1);
                updateVals.setAtIndex(ValueLayout.ADDRESS, 0, dataVal);

                MemorySegment attributesToUpdate =
                        (MemorySegment)
                                CF_DICTIONARY_CREATE.invokeExact(
                                        MemorySegment.NULL,
                                        updateKeys,
                                        updateVals,
                                        1L,
                                        K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                                        K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);

                status = (int) SEC_ITEM_UPDATE.invokeExact(queryDict, attributesToUpdate);
                CF_RELEASE.invokeExact(queryDict);
                CF_RELEASE.invokeExact(attributesToUpdate);
            }
            CF_RELEASE.invokeExact(dict);
            CF_RELEASE.invokeExact(keyStr);
            CF_RELEASE.invokeExact(dataVal);
            return status == 0;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to store secret in macOS Keychain", t);
        } finally {
            zeroFill(qualifiedKey);
        }
    }

    @Override
    public Optional<char[]> retrieve(char[] key) throws NativeVaultException {
        validateKey(key);
        char[] qualifiedKey = concatNamespaceAndKey(namespace, key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keyStr = createCFString(arena, qualifiedKey);

            MemorySegment keysArray = arena.allocate(ValueLayout.ADDRESS, 4);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 1, K_SEC_ATTR_ACCOUNT);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 2, K_SEC_RETURN_DATA);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 3, K_SEC_MATCH_LIMIT);

            MemorySegment valuesArray = arena.allocate(ValueLayout.ADDRESS, 4);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS_GENERIC_PASSWORD);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 1, keyStr);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 2, K_CF_BOOLEAN_TRUE);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 3, K_SEC_MATCH_LIMIT_ONE);

            MemorySegment queryDict =
                    (MemorySegment)
                            CF_DICTIONARY_CREATE.invokeExact(
                                    MemorySegment.NULL,
                                    keysArray,
                                    valuesArray,
                                    4L,
                                    K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                                    K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);

            MemorySegment resultData = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) SEC_ITEM_COPY_MATCHING.invokeExact(queryDict, resultData);
            CF_RELEASE.invokeExact(queryDict);
            CF_RELEASE.invokeExact(keyStr);

            if (status != 0) {
                return Optional.empty();
            }

            MemorySegment dataRef = resultData.get(ValueLayout.ADDRESS, 0);
            if (MemorySegment.NULL.equals(dataRef) || dataRef.address() == 0) {
                return Optional.empty();
            }

            try {
                long length = (long) CF_DATA_GET_LENGTH.invokeExact(dataRef);
                MemorySegment bytePtr = (MemorySegment) CF_DATA_GET_BYTE_PTR.invokeExact(dataRef);
                MemorySegment bounded = bytePtr.reinterpret(length);
                byte[] bytes = bounded.toArray(ValueLayout.JAVA_BYTE);
                char[] chars =
                        StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(bytes)).array();
                return Optional.of(chars);
            } finally {
                CF_RELEASE.invokeExact(dataRef);
            }
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to retrieve secret from macOS Keychain", t);
        } finally {
            zeroFill(qualifiedKey);
        }
    }

    @Override
    public boolean delete(char[] key) throws NativeVaultException {
        validateKey(key);
        char[] qualifiedKey = concatNamespaceAndKey(namespace, key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keyStr = createCFString(arena, qualifiedKey);

            MemorySegment keysArray = arena.allocate(ValueLayout.ADDRESS, 2);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 1, K_SEC_ATTR_ACCOUNT);

            MemorySegment valuesArray = arena.allocate(ValueLayout.ADDRESS, 2);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS_GENERIC_PASSWORD);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 1, keyStr);

            MemorySegment queryDict =
                    (MemorySegment)
                            CF_DICTIONARY_CREATE.invokeExact(
                                    MemorySegment.NULL,
                                    keysArray,
                                    valuesArray,
                                    2L,
                                    K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                                    K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);

            int status = (int) SEC_ITEM_DELETE.invokeExact(queryDict);
            CF_RELEASE.invokeExact(queryDict);
            CF_RELEASE.invokeExact(keyStr);
            return status == 0;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to delete secret from macOS Keychain", t);
        } finally {
            zeroFill(qualifiedKey);
        }
    }

    @Override
    public boolean exists(char[] key) throws NativeVaultException {
        validateKey(key);
        char[] qualifiedKey = concatNamespaceAndKey(namespace, key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keyStr = createCFString(arena, qualifiedKey);

            MemorySegment keysArray = arena.allocate(ValueLayout.ADDRESS, 3);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 1, K_SEC_ATTR_ACCOUNT);
            keysArray.setAtIndex(ValueLayout.ADDRESS, 2, K_SEC_MATCH_LIMIT);

            MemorySegment valuesArray = arena.allocate(ValueLayout.ADDRESS, 3);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 0, K_SEC_CLASS_GENERIC_PASSWORD);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 1, keyStr);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, 2, K_SEC_MATCH_LIMIT_ONE);

            MemorySegment queryDict =
                    (MemorySegment)
                            CF_DICTIONARY_CREATE.invokeExact(
                                    MemorySegment.NULL,
                                    keysArray,
                                    valuesArray,
                                    3L,
                                    K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                                    K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);

            MemorySegment resultData = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) SEC_ITEM_COPY_MATCHING.invokeExact(queryDict, resultData);
            CF_RELEASE.invokeExact(queryDict);
            CF_RELEASE.invokeExact(keyStr);

            if (status == 0) {
                MemorySegment dataRef = resultData.get(ValueLayout.ADDRESS, 0);
                if (!MemorySegment.NULL.equals(dataRef) && dataRef.address() != 0) {
                    CF_RELEASE.invokeExact(dataRef);
                }
                return true;
            }
            return false;
        } catch (Throwable t) {
            if (t instanceof Error error) {
                throw error;
            }
            throw new NativeVaultException("Failed to check secret existence in macOS Keychain", t);
        } finally {
            zeroFill(qualifiedKey);
        }
    }

    private MemorySegment createCFString(Arena arena, char[] chars) throws Throwable {
        byte[] bytes = new String(chars).getBytes(StandardCharsets.UTF_8);
        MemorySegment cStr = arena.allocate(bytes.length + 1L);
        cStr.asByteBuffer().put(bytes).put((byte) 0);
        return (MemorySegment)
                CF_STRING_CREATE_WITH_C_STRING.invokeExact(
                        MemorySegment.NULL, cStr, 0x08000000 /* kCFStringEncodingUTF8 */);
    }

    private MemorySegment createCFData(Arena arena, char[] chars) throws Throwable {
        byte[] bytes = new String(chars).getBytes(StandardCharsets.UTF_8);
        MemorySegment dataSeg = arena.allocate(bytes.length);
        dataSeg.asByteBuffer().put(bytes);
        return (MemorySegment)
                CF_DATA_CREATE.invokeExact(MemorySegment.NULL, dataSeg, (long) bytes.length);
    }
}
