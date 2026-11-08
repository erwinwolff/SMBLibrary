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
    /// .NET 10 uses the AesGcm class of the platform; .NET Framework has none, so a managed implementation is used there.
    /// </summary>
    public static class AesGcmCipher
    {
        public const int NonceLength = 12;
        public const int TagLength = 16;

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, out byte[] tag)
        {
            Validate(key, nonce);
#if NET
            byte[] result = new byte[data.Length];
            tag = new byte[TagLength];
            using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, TagLength))
            {
                aesGcm.Encrypt(nonce, data, result, tag, associatedData);
            }
            return result;
#else
            return AesGcmManaged.Encrypt(key, nonce, data, associatedData, out tag);
#endif
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
            byte[] result = new byte[encryptedData.Length];
            using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, TagLength))
            {
                // Throws AuthenticationTagMismatchException, a CryptographicException
                aesGcm.Decrypt(nonce, encryptedData, tag, result, associatedData);
            }
            return result;
#else
            return AesGcmManaged.DecryptAndAuthenticate(key, nonce, encryptedData, associatedData, tag);
#endif
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
    /// for the counter blocks), GHASH uses the 4 bit table method by Shoup. Compiled for every target so the tests
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
        /// GHASH over GF(2^128) with precomputed multiples of H (4 bit tables)
        /// </summary>
        private sealed class GHash
        {
            // Reduction of the 4 bits shifted out at the low end, already in the bit reflected representation of GCM
            private static readonly ulong[] Last4 =
            {
                0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
                0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
            };

            private readonly ulong[] m_high = new ulong[16];
            private readonly ulong[] m_low = new ulong[16];

            public GHash(byte[] h)
            {
                ulong vh = BigEndianConverter.ToUInt64(h, 0);
                ulong vl = BigEndianConverter.ToUInt64(h, 8);

                // Entry 8 is H itself (the bit order is reversed), entries 4, 2 and 1 are H * x, H * x^2 and H * x^3
                m_high[8] = vh;
                m_low[8] = vl;
                for (int index = 4; index > 0; index >>= 1)
                {
                    ulong reduction = (vl & 1) != 0 ? 0xe100000000000000UL : 0UL;
                    vl = (vh << 63) | (vl >> 1);
                    vh = (vh >> 1) ^ reduction;
                    m_high[index] = vh;
                    m_low[index] = vl;
                }

                // The other entries are sums of those
                for (int index = 2; index <= 8; index *= 2)
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

            public byte[] Compute(byte[] associatedData, byte[] cipherText)
            {
                byte[] y = new byte[BlockSize];
                Absorb(y, associatedData);
                Absorb(y, cipherText);

                // len(A) || len(C) in bits, 64 bit big endian each
                byte[] lengths = new byte[BlockSize];
                BigEndianWriter.WriteUInt64(lengths, 0, (ulong)associatedData.Length * 8);
                BigEndianWriter.WriteUInt64(lengths, 8, (ulong)cipherText.Length * 8);
                for (int index = 0; index < BlockSize; index++)
                {
                    y[index] ^= lengths[index];
                }
                MultiplyByH(y);
                return y;
            }

            // Y = (Y xor block) * H for every block; the last block is padded with zeros
            private void Absorb(byte[] y, byte[] data)
            {
                for (int offset = 0; offset < data.Length; offset += BlockSize)
                {
                    int length = Math.Min(BlockSize, data.Length - offset);
                    for (int index = 0; index < length; index++)
                    {
                        y[index] ^= data[offset + index];
                    }
                    MultiplyByH(y);
                }
            }

            private void MultiplyByH(byte[] x)
            {
                int low = x[15] & 0x0F;
                ulong zh = m_high[low];
                ulong zl = m_low[low];

                for (int index = 15; index >= 0; index--)
                {
                    low = x[index] & 0x0F;
                    int high = (x[index] >> 4) & 0x0F;

                    if (index != 15)
                    {
                        int remainder = (int)(zl & 0x0F);
                        zl = (zh << 60) | (zl >> 4);
                        zh = (zh >> 4) ^ (Last4[remainder] << 48);
                        zh ^= m_high[low];
                        zl ^= m_low[low];
                    }

                    int remainder2 = (int)(zl & 0x0F);
                    zl = (zh << 60) | (zl >> 4);
                    zh = (zh >> 4) ^ (Last4[remainder2] << 48);
                    zh ^= m_high[high];
                    zl ^= m_low[high];
                }

                BigEndianWriter.WriteUInt64(x, 0, zh);
                BigEndianWriter.WriteUInt64(x, 8, zl);
            }
        }
    }
}
