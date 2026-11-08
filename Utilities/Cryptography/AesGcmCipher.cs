/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Security.Cryptography;

namespace Utilities
{
    /// <summary>
    /// AES in Galois/Counter Mode (NIST SP 800-38D) with a 96 bit nonce and a 128 bit tag, the variant SMB 3.1.1 uses.
    /// .NET 10 uses the AesGcm class of the platform, .NET Framework uses Windows CNG (both hardware accelerated); the
    /// managed implementation is the fallback when neither is available.
    /// </summary>
    public static class AesGcmCipher
    {
        public const int NonceLength = 12;
        public const int TagLength = 16;

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, out byte[] tag)
        {
            Validate(key, nonce);
#if NET
            if (System.Security.Cryptography.AesGcm.IsSupported)
            {
                byte[] result = new byte[data.Length];
                tag = new byte[TagLength];
                using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, TagLength))
                {
                    aesGcm.Encrypt(nonce, data, result, tag, associatedData);
                }
                return result;
            }
#else
            if (BCryptAead.IsGcmSupported)
            {
                return BCryptAead.EncryptGcm(key, nonce, data, 0, data.Length, associatedData, TagLength, out tag);
            }
#endif
            return AesGcmManaged.Encrypt(key, nonce, data, associatedData, out tag);
        }

        /// <exception cref="CryptographicException">The data or the associated data was changed, or the key is wrong</exception>
        public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] tag)
        {
            Validate(key, nonce);
            if (tag == null || tag.Length != TagLength)
            {
                throw new ArgumentException("tag must be 16 bytes long");
            }
#if NET
            if (System.Security.Cryptography.AesGcm.IsSupported)
            {
                byte[] result = new byte[encryptedData.Length];
                using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, TagLength))
                {
                    // Throws AuthenticationTagMismatchException, a CryptographicException
                    aesGcm.Decrypt(nonce, encryptedData, tag, result, associatedData);
                }
                return result;
            }
#else
            if (BCryptAead.IsGcmSupported)
            {
                return BCryptAead.DecryptGcm(key, nonce, encryptedData, associatedData, tag);
            }
#endif
            return AesGcmManaged.DecryptAndAuthenticate(key, nonce, encryptedData, associatedData, tag);
        }

        /// <summary>
        /// AES-GMAC (RFC 4543): the GCM tag of the data without encrypting anything
        /// </summary>
        public static byte[] ComputeGmac(byte[] key, byte[] nonce, byte[] data, int offset, int length)
        {
            Validate(key, nonce);
#if NET
            if (System.Security.Cryptography.AesGcm.IsSupported)
            {
                // The message is passed as a slice: no copy
                byte[] gmac = new byte[TagLength];
                using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, TagLength))
                {
                    aesGcm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, gmac, new ReadOnlySpan<byte>(data, offset, length));
                }
                return gmac;
            }
#else
            if (BCryptAead.IsGcmSupported)
            {
                // The message is passed as a pointer into the array: no copy
                return BCryptAead.ComputeGmac(key, nonce, data, offset, length, TagLength);
            }
#endif
            byte[] associatedData = ByteReader.ReadBytes(data, offset, length);
            byte[] tag;
            AesGcmManaged.Encrypt(key, nonce, new byte[0], associatedData, out tag);
            return tag;
        }

        private static void Validate(byte[] key, byte[] nonce)
        {
            if (key == null || (key.Length != 16 && key.Length != 24 && key.Length != 32))
            {
                throw new ArgumentException("key must be 16, 24 or 32 bytes long");
            }

            if (nonce == null || nonce.Length != NonceLength)
            {
                throw new ArgumentException("nonce must be 12 bytes long");
            }
        }
    }

    /// <summary>
    /// Managed AES-GCM for .NET Framework, which has no AES-GCM of its own. AES itself comes from the platform (ECB
    /// for the counter blocks), GHASH uses the 8 bit table method by Shoup. Compiled for every target so the tests
    /// can compare it with the AesGcm class of .NET.
    /// </summary>
    internal static class AesGcmManaged
    {
        private const int BlockSize = 16;

        // Counter blocks encrypted per call of the platform AES; bounds the memory for large messages
        private const int BlocksPerBatch = 4096;

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, out byte[] tag)
        {
            associatedData = associatedData ?? new byte[0];

            using (Aes aes = CreateAes(key))
            using (ICryptoTransform ecb = aes.CreateEncryptor())
            {
                GHash ghash = new GHash(EncryptBlock(ecb, new byte[BlockSize]));
                byte[] j0 = BuildJ0(nonce);

                byte[] result = ApplyCounterMode(ecb, j0, data);
                byte[] s = ghash.Compute(associatedData, result);
                tag = ByteUtils.XOR(EncryptBlock(ecb, j0), 0, s, 0, BlockSize);
                return result;
            }
        }

        public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] tag)
        {
            associatedData = associatedData ?? new byte[0];

            using (Aes aes = CreateAes(key))
            using (ICryptoTransform ecb = aes.CreateEncryptor())
            {
                GHash ghash = new GHash(EncryptBlock(ecb, new byte[BlockSize]));
                byte[] j0 = BuildJ0(nonce);

                // Authenticate before decrypting: nothing of a forged message is returned
                byte[] s = ghash.Compute(associatedData, encryptedData);
                byte[] expectedTag = ByteUtils.XOR(EncryptBlock(ecb, j0), 0, s, 0, BlockSize);
                if (!FixedTimeEquals(expectedTag, tag))
                {
                    throw new CryptographicException("The computed authentication value did not match the input");
                }

                return ApplyCounterMode(ecb, j0, encryptedData);
            }
        }

        private static Aes CreateAes(byte[] key)
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            return aes;
        }

        private static byte[] EncryptBlock(ICryptoTransform ecb, byte[] block)
        {
            byte[] output = new byte[BlockSize];
            ecb.TransformBlock(block, 0, BlockSize, output, 0);
            return output;
        }

        // J0 = IV || 0^31 || 1 for a 96 bit IV
        private static byte[] BuildJ0(byte[] nonce)
        {
            byte[] j0 = new byte[BlockSize];
            Array.Copy(nonce, j0, AesGcmCipher.NonceLength);
            j0[15] = 1;
            return j0;
        }

        /// <summary>
        /// GCTR with the counter starting at inc32(J0)
        /// </summary>
        private static byte[] ApplyCounterMode(ICryptoTransform ecb, byte[] j0, byte[] input)
        {
            byte[] output = new byte[input.Length];
            int totalBlocks = (input.Length + BlockSize - 1) / BlockSize;
            uint counter = BigEndianConverter.ToUInt32(j0, 12);
            byte[] counterBlocks = new byte[Math.Min(totalBlocks, BlocksPerBatch) * BlockSize];
            byte[] keyStream = new byte[counterBlocks.Length];

            for (int firstBlock = 0; firstBlock < totalBlocks; firstBlock += BlocksPerBatch)
            {
                int blockCount = Math.Min(BlocksPerBatch, totalBlocks - firstBlock);
                for (int index = 0; index < blockCount; index++)
                {
                    counter++;
                    Array.Copy(j0, 0, counterBlocks, index * BlockSize, 12);
                    BigEndianWriter.WriteUInt32(counterBlocks, index * BlockSize + 12, counter);
                }

                ecb.TransformBlock(counterBlocks, 0, blockCount * BlockSize, keyStream, 0);

                int offset = firstBlock * BlockSize;
                int length = Math.Min(blockCount * BlockSize, input.Length - offset);
                for (int index = 0; index < length; index++)
                {
                    output[offset + index] = (byte)(input[offset + index] ^ keyStream[index]);
                }
            }

            return output;
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            int difference = 0;
            for (int index = 0; index < left.Length; index++)
            {
                difference |= left[index] ^ right[index];
            }
            return difference == 0;
        }

        /// <summary>
        /// GHASH over GF(2^128) with precomputed multiples of H for every byte value (Shoup's 8 bit tables, 4 KB per
        /// key): one table lookup and one 8 bit shift per byte instead of 8 single bit steps
        /// </summary>
        private sealed class GHash
        {
            // Reduction of the 8 bits shifted out at the low end when multiplying by x^8 (bit reflected, as GCM uses)
            private static readonly ulong[] Reduction8 = BuildReductionTable();

            private readonly ulong[] m_high = new ulong[256];
            private readonly ulong[] m_low = new ulong[256];

            public GHash(byte[] h)
            {
                // The first bit of a byte is the lowest power of x: entry 0x80 is H, 0x40 is H * x, ... 0x01 is H * x^7
                ulong vh = BigEndianConverter.ToUInt64(h, 0);
                ulong vl = BigEndianConverter.ToUInt64(h, 8);
                m_high[0x80] = vh;
                m_low[0x80] = vl;
                for (int index = 0x40; index > 0; index >>= 1)
                {
                    ulong reduction = (vl & 1) != 0 ? 0xe100000000000000UL : 0UL;
                    vl = (vh << 63) | (vl >> 1);
                    vh = (vh >> 1) ^ reduction;
                    m_high[index] = vh;
                    m_low[index] = vl;
                }

                // Multiplication is linear: every other entry is the sum of the entries of its bits
                for (int index = 2; index <= 0x80; index *= 2)
                {
                    vh = m_high[index];
                    vl = m_low[index];
                    for (int j = 1; j < index; j++)
                    {
                        m_high[index + j] = vh ^ m_high[j];
                        m_low[index + j] = vl ^ m_low[j];
                    }
                }
            }

            private static ulong[] BuildReductionTable()
            {
                // Shifting right by 8 is 8 single bit shifts; the bits that fall off are reduced into the top 64 bits.
                // That only depends on the 8 bits that fall off, so it can be precomputed for every byte value.
                ulong[] table = new ulong[256];
                for (int value = 0; value < 256; value++)
                {
                    ulong vh = 0;
                    ulong vl = (ulong)value;
                    for (int bit = 0; bit < 8; bit++)
                    {
                        ulong reduction = (vl & 1) != 0 ? 0xe100000000000000UL : 0UL;
                        vl = (vh << 63) | (vl >> 1);
                        vh = (vh >> 1) ^ reduction;
                    }
                    table[value] = vh;
                }
                return table;
            }

            public byte[] Compute(byte[] associatedData, byte[] cipherText)
            {
                // The state Y is kept as two 64 bit halves (big endian), no byte array per block
                ulong yh = 0;
                ulong yl = 0;
                Absorb(ref yh, ref yl, associatedData);
                Absorb(ref yh, ref yl, cipherText);

                // len(A) || len(C) in bits, 64 bit big endian each
                yh ^= (ulong)associatedData.Length * 8;
                yl ^= (ulong)cipherText.Length * 8;
                MultiplyByH(ref yh, ref yl);

                byte[] result = new byte[BlockSize];
                BigEndianWriter.WriteUInt64(result, 0, yh);
                BigEndianWriter.WriteUInt64(result, 8, yl);
                return result;
            }

            // Y = (Y xor block) * H for every block; the last block is padded with zeros
            private void Absorb(ref ulong yh, ref ulong yl, byte[] data)
            {
                int fullBlocksEnd = data.Length - data.Length % BlockSize;
                for (int offset = 0; offset < fullBlocksEnd; offset += BlockSize)
                {
                    yh ^= ReadUInt64(data, offset);
                    yl ^= ReadUInt64(data, offset + 8);
                    MultiplyByH(ref yh, ref yl);
                }

                if (fullBlocksEnd < data.Length)
                {
                    byte[] last = new byte[BlockSize];
                    Array.Copy(data, fullBlocksEnd, last, 0, data.Length - fullBlocksEnd);
                    yh ^= ReadUInt64(last, 0);
                    yl ^= ReadUInt64(last, 8);
                    MultiplyByH(ref yh, ref yl);
                }
            }

            private static ulong ReadUInt64(byte[] buffer, int offset)
            {
                return ((ulong)buffer[offset] << 56) | ((ulong)buffer[offset + 1] << 48) | ((ulong)buffer[offset + 2] << 40) | ((ulong)buffer[offset + 3] << 32) |
                       ((ulong)buffer[offset + 4] << 24) | ((ulong)buffer[offset + 5] << 16) | ((ulong)buffer[offset + 6] << 8) | buffer[offset + 7];
            }

            // Y = Y * H, Horner's scheme over the bytes: from the highest power of x (the last byte, the low byte of
            // yl) down to the first byte (the high byte of yh)
            private void MultiplyByH(ref ulong yh, ref ulong yl)
            {
                ulong[] high = m_high;
                ulong[] low = m_low;
                ulong[] reduction = Reduction8;
                ulong zh = 0;
                ulong zl = 0;

                for (int shift = 0; shift < 64; shift += 8)
                {
                    int value = (int)(yl >> shift) & 0xFF;
                    ulong fallingOff = zl & 0xFF;
                    zl = (zh << 56) | (zl >> 8);
                    zh = (zh >> 8) ^ reduction[fallingOff] ^ high[value];
                    zl ^= low[value];
                }

                for (int shift = 0; shift < 64; shift += 8)
                {
                    int value = (int)(yh >> shift) & 0xFF;
                    ulong fallingOff = zl & 0xFF;
                    zl = (zh << 56) | (zl >> 8);
                    zh = (zh >> 8) ^ reduction[fallingOff] ^ high[value];
                    zl ^= low[value];
                }

                yh = zh;
                yl = zl;
            }
        }
    }
}
