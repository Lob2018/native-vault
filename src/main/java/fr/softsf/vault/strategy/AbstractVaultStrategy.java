/*
 * NativeVault - Copyright © 2026-present SOFT64.FR Lob2018
 * Licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license at: https://github.com/Lob2018/native-vault/blob/main/LICENSE
 */
package fr.softsf.vault.strategy;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Objects;

public abstract sealed class AbstractVaultStrategy implements VaultStrategy
        permits MacKeychainStrategy, LinuxKeyringStrategy, WindowsCredentialManagerStrategy {

    /**
     * Overwrites the specified memory segment with zeros to ensure security.
     *
     * @param segment the memory segment to clear
     */
    void zeroFill(MemorySegment segment) {
        if (segment != null && segment.address() != 0 && !segment.equals(MemorySegment.NULL)) {
            segment.fill((byte) 0);
        }
    }

    /**
     * Allocates and populates a memory segment for the given character data.
     *
     * @param arena the memory arena
     * @param data the character array data
     * @param charset the charset to use for encoding
     * @return the allocated memory segment
     * @throws IllegalArgumentException if {@code arena}, {@code data}, or {@code charset} is null,
     *     or if {@code data} is empty
     */
    MemorySegment allocateSegment(Arena arena, char[] data, Charset charset) {
        if (Objects.isNull(arena)) {
            throw new IllegalArgumentException("Arena cannot be null");
        }
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("Data cannot be null or empty");
        }
        if (Objects.isNull(charset)) {
            throw new IllegalArgumentException("Charset cannot be null");
        }
        java.nio.ByteBuffer byteBuffer = charset.encode(CharBuffer.wrap(data));
        MemorySegment segment = arena.allocate(byteBuffer.remaining());
        segment.copyFrom(MemorySegment.ofBuffer(byteBuffer));
        byteBuffer.position(0);
        while (byteBuffer.hasRemaining()) {
            byteBuffer.put((byte) 0);
        }
        return segment;
    }
}
