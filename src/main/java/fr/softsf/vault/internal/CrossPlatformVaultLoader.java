package fr.softsf.vault.internal;

import org.apache.commons.lang3.StringUtils;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.util.Locale;
import java.util.Objects;

/**
 * Utility loader for native platform functions using the FFM API.
 */
public final class CrossPlatformVaultLoader {
    private static final Linker LINKER = Linker.nativeLinker();

    /**
     * Private constructor to prevent instantiation.
     */
    private CrossPlatformVaultLoader() {}

    /**
     * Loads a native function handle from a given library and function name.
     *
     * @param libraryName the library name or path
     * @param functionName the function name
     * @param descriptor the function descriptor
     * @return the method handle for the native function
     * @throws IllegalArgumentException if {@code libraryName} is blank, {@code functionName} is blank, or {@code descriptor} is null
     */
    public static MethodHandle loadNativeFunction(String libraryName, String functionName, FunctionDescriptor descriptor) {
        if (StringUtils.isBlank(libraryName)) {
            throw new IllegalArgumentException("LibraryName must not be blank");
        }
        if (StringUtils.isBlank(functionName)) {
            throw new IllegalArgumentException("FunctionName must not be blank");
        }
        if (Objects.isNull(descriptor)) {
            throw new IllegalArgumentException("Descriptor must not be null");
        }
        SymbolLookup lookup;
        if (libraryName.contains("/") || libraryName.endsWith(".so.0") || libraryName.toLowerCase(Locale.ROOT).endsWith(".dll")) {
            lookup = SymbolLookup.libraryLookup(libraryName, Arena.global());
        } else if (libraryName.equalsIgnoreCase("Advapi32")) {
            lookup = SymbolLookup.libraryLookup(libraryName + ".dll", Arena.global());
        } else {
            lookup = LINKER.defaultLookup();
        }
        if (lookup.find(functionName).isEmpty() && !libraryName.equalsIgnoreCase("Advapi32")) {
            lookup = SymbolLookup.libraryLookup(libraryName, Arena.global());
        }
        return lookup.find(functionName)
                .map(addr -> LINKER.downcallHandle(addr, descriptor))
                .orElseThrow(() -> new UnsatisfiedLinkError("Failed to load native function: " + functionName));
    }
}