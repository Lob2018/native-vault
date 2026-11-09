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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

import fr.softsf.vault.exception.NativeVaultException;
import fr.softsf.vault.internal.CrossPlatformVaultLoader;

/**
 * macOS Keychain implementation of the VaultStrategy interface utilizing the FFM API with proper
 * CoreFoundation dictionary allocation, native resource release, and heap memory hygiene.
 *
 * @see <a href="https://developer.apple.com/documentation/security/keychain-services">Keychain
 *     Services Reference</a>
 * @see <a href="https://developer.apple.com/documentation/corefoundation">CoreFoundation
 *     Reference</a>
 */
public final class MacKeychainStrategy extends AbstractVaultStrategy {
    private static final String LIB_PATH =
            "/System/Library/Frameworks/Security.framework/Security"; // NOSONAR
    private static final String CF_LIB_PATH =
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"; // NOSONAR
    private static final int K_CF_STRING_ENCODING_UTF8 = 0x08000000;

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

    /**
     * Initializes a new instance of the {@code MacKeychainStrategy} with a custom namespace.
     *
     * @param namespace the isolated namespace character array used as an account prefix for
     *     Keychain items
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
        char[] qualifiedKey = concatNamespaceAndKey(namespace, key);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keyStr = createCFString(arena, qualifiedKey);
            MemorySegment dataVal = createCFData(arena, secret);

            MemorySegment dict =
                    createDictionary(
                            arena,
                            new MemorySegment[] {K_SEC_CLASS, K_SEC_ATTR_ACCOUNT, K_SEC_VALUE_DATA},
                            new MemorySegment[] {K_SEC_CLASS_GENERIC_PASSWORD, keyStr, dataVal});

            int status = (int) SEC_ITEM_ADD.invokeExact(dict, MemorySegment.NULL);
            if (status == -25299) { // errSecDuplicateItem
                MemorySegment queryDict =
                        createDictionary(
                                arena,
                                new MemorySegment[] {K_SEC_CLASS, K_SEC_ATTR_ACCOUNT},
                                new MemorySegment[] {K_SEC_CLASS_GENERIC_PASSWORD, keyStr});

                MemorySegment attributesToUpdate =
                        createDictionary(
                                arena,
                                new MemorySegment[] {K_SEC_VALUE_DATA},
                                new MemorySegment[] {dataVal});

                status = (int) SEC_ITEM_UPDATE.invokeExact(queryDict, attributesToUpdate);
                releaseAll(queryDict, attributesToUpdate);
            }
            releaseAll(dict, keyStr, dataVal);
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

            MemorySegment queryDict =
                    createDictionary(
                            arena,
                            new MemorySegment[] {
                                K_SEC_CLASS,
                                K_SEC_ATTR_ACCOUNT,
                                K_SEC_RETURN_DATA,
                                K_SEC_MATCH_LIMIT
                            },
                            new MemorySegment[] {
                                K_SEC_CLASS_GENERIC_PASSWORD,
                                keyStr,
                                K_CF_BOOLEAN_TRUE,
                                K_SEC_MATCH_LIMIT_ONE
                            });

            MemorySegment resultData = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) SEC_ITEM_COPY_MATCHING.invokeExact(queryDict, resultData);
            releaseAll(queryDict, keyStr);

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
                char[] chars = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes)).array();
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

            MemorySegment queryDict =
                    createDictionary(
                            arena,
                            new MemorySegment[] {K_SEC_CLASS, K_SEC_ATTR_ACCOUNT},
                            new MemorySegment[] {K_SEC_CLASS_GENERIC_PASSWORD, keyStr});

            int status = (int) SEC_ITEM_DELETE.invokeExact(queryDict);
            releaseAll(queryDict, keyStr);
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

            MemorySegment queryDict =
                    createDictionary(
                            arena,
                            new MemorySegment[] {
                                K_SEC_CLASS, K_SEC_ATTR_ACCOUNT, K_SEC_MATCH_LIMIT
                            },
                            new MemorySegment[] {
                                K_SEC_CLASS_GENERIC_PASSWORD, keyStr, K_SEC_MATCH_LIMIT_ONE
                            });

            MemorySegment resultData = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) SEC_ITEM_COPY_MATCHING.invokeExact(queryDict, resultData);
            releaseAll(queryDict, keyStr);

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

    /**
     * Creates a CoreFoundation dictionary from the provided keys and values arrays.
     *
     * @param arena the memory arena used for allocations
     * @param keys the array of memory segments representing dictionary keys
     * @param values the array of memory segments representing dictionary values
     * @return a memory segment pointing to the created CoreFoundation dictionary
     * @throws Throwable if native method invocation fails
     */
    private static MemorySegment createDictionary(
            Arena arena, MemorySegment[] keys, MemorySegment[] values) throws Throwable {
        validateArena(arena);
        if (keys == null || keys.length == 0) {
            throw new IllegalArgumentException("Keys cannot be null or empty");
        }
        if (values == null || values.length == 0) {
            throw new IllegalArgumentException("Values cannot be null or empty");
        }
        int size = keys.length;
        MemorySegment keysArray = arena.allocate(ValueLayout.ADDRESS, size);
        MemorySegment valuesArray = arena.allocate(ValueLayout.ADDRESS, size);

        for (int i = 0; i < size; i++) {
            keysArray.setAtIndex(ValueLayout.ADDRESS, i, keys[i]);
            valuesArray.setAtIndex(ValueLayout.ADDRESS, i, values[i]);
        }

        return (MemorySegment)
                CF_DICTIONARY_CREATE.invokeExact(
                        MemorySegment.NULL,
                        keysArray,
                        valuesArray,
                        (long) size,
                        K_CF_TYPE_DICTIONARY_KEY_CALLBACKS,
                        K_CF_TYPE_DICTIONARY_VALUE_CALLBACKS);
    }

    /**
     * Releases multiple CoreFoundation memory segments safely by invoking CFRelease.
     *
     * @param segments the array of memory segments to release
     * @throws Throwable if native method invocation fails
     */
    private static void releaseAll(MemorySegment... segments) throws Throwable {
        if (segments == null) {
            throw new IllegalArgumentException("Segments array cannot be null");
        }
        for (MemorySegment segment : segments) {
            if (segment != null && !MemorySegment.NULL.equals(segment) && segment.address() != 0) {
                CF_RELEASE.invokeExact(segment);
            }
        }
    }

    /**
     * Encodes character data into UTF-8 format using a ByteBuffer wrapper.
     *
     * @param chars the character array to encode
     * @return the resulting ByteBuffer containing UTF-8 encoded bytes
     */
    private static ByteBuffer encodeUtf8(char[] chars) {
        if (chars == null || chars.length == 0) {
            throw new IllegalArgumentException("Chars cannot be null or empty");
        }
        return StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
    }

    /**
     * Creates a CoreFoundation string segment from the given character data.
     *
     * @param arena the memory arena used for allocations
     * @param chars the character array data
     * @return a memory segment representing the CoreFoundation string
     * @throws Throwable if native method invocation fails
     */
    private static MemorySegment createCFString(Arena arena, char[] chars) throws Throwable {
        validateArena(arena);
        ByteBuffer byteBuffer = encodeUtf8(chars);
        int limit = byteBuffer.remaining();
        MemorySegment cStr = arena.allocate(limit + 1L);
        cStr.asByteBuffer().put(byteBuffer);
        cStr.set(ValueLayout.JAVA_BYTE, limit, (byte) 0);
        return (MemorySegment)
                CF_STRING_CREATE_WITH_C_STRING.invokeExact(
                        MemorySegment.NULL, cStr, K_CF_STRING_ENCODING_UTF8);
    }

    /**
     * Creates a CoreFoundation data segment from the given character data.
     *
     * @param arena the memory arena used for allocations
     * @param chars the character array data
     * @return a memory segment representing the CoreFoundation data
     * @throws Throwable if native method invocation fails
     */
    private static MemorySegment createCFData(Arena arena, char[] chars) throws Throwable {
        validateArena(arena);
        ByteBuffer byteBuffer = encodeUtf8(chars);
        long limit = byteBuffer.remaining();
        MemorySegment dataSeg = arena.allocate(limit);
        dataSeg.asByteBuffer().put(byteBuffer);
        return (MemorySegment) CF_DATA_CREATE.invokeExact(MemorySegment.NULL, dataSeg, limit);
    }

    /**
     * Validates that the provided Arena is not null.
     *
     * @param arena the arena to validate
     * @throws IllegalArgumentException if the arena is null
     */
    private static void validateArena(Arena arena) {
        if (Objects.isNull(arena)) {
            throw new IllegalArgumentException("Arena cannot be null");
        }
    }
}
