/* Copyright (C) 2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// Implements the Counter with CBC-MAC (CCM) detailed in RFC 3610.
    /// .NET 10 uses the AesCcm class of the platform, .NET Framework uses Windows CNG (both hardware accelerated).
    /// AesCcmManaged is the fallback, in which the AES operations themselves still run in the platform AES (AES-NI).
    /// </summary>
    public static class AesCcm
    {
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength, out byte[] signature)
        {
            AesCcmManaged.Validate(nonce, signatureLength);
#if NET
            if (System.Security.Cryptography.AesCcm.IsSupported)
            {
                byte[] result = new byte[data.Length];
                signature = new byte[signatureLength];
                using (System.Security.Cryptography.AesCcm aesCcm = new System.Security.Cryptography.AesCcm(key))
                {
                    aesCcm.Encrypt(nonce, data, result, signature, associatedData);
                }
                return result;
            }
#else
            if (BCryptAead.IsCcmSupported)
            {
                return BCryptAead.EncryptCcm(key, nonce, data, associatedData, signatureLength, out signature);
            }
#endif
            return AesCcmManaged.Encrypt(key, nonce, data, associatedData, signatureLength, out signature);
        }

        /// <exception cref="CryptographicException">The data or the associated data was changed, or the key is wrong</exception>
        public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] signature)
        {
            AesCcmManaged.Validate(nonce, signature.Length);
#if NET
            if (System.Security.Cryptography.AesCcm.IsSupported)
            {
                byte[] result = new byte[encryptedData.Length];
                using (System.Security.Cryptography.AesCcm aesCcm = new System.Security.Cryptography.AesCcm(key))
                {
                    // Throws AuthenticationTagMismatchException, a CryptographicException
                    aesCcm.Decrypt(nonce, encryptedData, signature, result, associatedData);
                }
                return result;
            }
#else
            if (BCryptAead.IsCcmSupported)
            {
                return BCryptAead.DecryptCcm(key, nonce, encryptedData, associatedData, signature);
            }
#endif
            return AesCcmManaged.DecryptAndAuthenticate(key, nonce, encryptedData, associatedData, signature);
        }
    }

    /// <summary>
    /// Managed CCM (RFC 3610). The key stream (CTR) and the CBC-MAC are each computed with a single call of the platform
    /// AES over one buffer, so the block cipher itself is hardware accelerated; only the framing is managed code.
    /// Compiled for every target so the tests can compare it with the AesCcm class of .NET.
    /// </summary>
    internal static class AesCcmManaged
    {
        private const int BlockSize = 16;

        public static void Validate(byte[] nonce, int signatureLength)
        {
            if (nonce == null || nonce.Length < 7 || nonce.Length > 13)
            {
                throw new ArgumentException("nonce length must be between 7 and 13 bytes");
            }

            if (signatureLength < 4 || signatureLength > 16 || (signatureLength % 2 == 1))
            {
                throw new ArgumentException("signature length must be an even number between 4 and 16 bytes");
            }
        }

        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength, out byte[] signature)
        {
            Validate(nonce, signatureLength);
            associatedData = associatedData ?? new byte[0];

            using (Aes aes = CreateAes(key))
            {
                byte[] keyStream = BuildKeyStream(aes, nonce, data.Length);
                byte[] mac = CalculateMac(aes, nonce, data, associatedData, signatureLength);

                // S0 (the first key stream block) encrypts the MAC, the rest encrypts the data
                signature = ByteUtils.XOR(keyStream, 0, mac, 0, signatureLength);
                return Xor(data, keyStream, BlockSize);
            }
        }

        public static byte[] DecryptAndAuthenticate(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] signature)
        {
            Validate(nonce, signature.Length);
            associatedData = associatedData ?? new byte[0];

            using (Aes aes = CreateAes(key))
            {
                byte[] keyStream = BuildKeyStream(aes, nonce, encryptedData.Length);
                byte[] data = Xor(encryptedData, keyStream, BlockSize);

                byte[] mac = CalculateMac(aes, nonce, data, associatedData, signature.Length);
                byte[] expectedSignature = ByteUtils.XOR(keyStream, 0, mac, 0, signature.Length);
                if (!FixedTimeEquals(expectedSignature, signature))
                {
                    throw new CryptographicException("The computed authentication value did not match the input");
                }
                return data;
            }
        }

        private static Aes CreateAes(byte[] key)
        {
            Aes aes = Aes.Create();
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            return aes;
        }

        /// <summary>
        /// CBC-MAC over B0 || encoded associated data || data, each part padded to the block size
        /// </summary>
        private static byte[] CalculateMac(Aes aes, byte[] nonce, byte[] data, byte[] associatedData, int signatureLength)
        {
            if (associatedData.Length >= 65280)
            {
                throw new NotSupportedException("Associated data length of 65280 or more is not supported");
            }

            int associatedDataPart = associatedData.Length > 0 ? PadToBlock(2 + associatedData.Length) : 0;
            byte[] input = new byte[BlockSize + associatedDataPart + PadToBlock(data.Length)];

            WriteB0Block(input, nonce, associatedData.Length > 0, signatureLength, data.Length);
            int offset = BlockSize;
            if (associatedData.Length > 0)
            {
                BigEndianWriter.WriteUInt16(input, offset, (ushort)associatedData.Length);
                Array.Copy(associatedData, 0, input, offset + 2, associatedData.Length);
                offset += associatedDataPart;
            }
            Array.Copy(data, 0, input, offset, data.Length);

            aes.Mode = CipherMode.CBC;
            aes.IV = new byte[BlockSize];
            byte[] encrypted;
            using (ICryptoTransform cbc = aes.CreateEncryptor())
            {
                encrypted = cbc.TransformFinalBlock(input, 0, input.Length);
            }
            return ByteReader.ReadBytes(encrypted, encrypted.Length - BlockSize, signatureLength);
        }

        /// <summary>
        /// A0 (encrypts the MAC) followed by A1..An (encrypt the data)
        /// </summary>
        private static byte[] BuildKeyStream(Aes aes, byte[] nonce, int dataLength)
        {
            int blockCount = 1 + (dataLength + BlockSize - 1) / BlockSize;
            byte[] counterBlocks = new byte[blockCount * BlockSize];
            int lengthFieldLength = 15 - nonce.Length;

            for (int index = 0; index < blockCount; index++)
            {
                int offset = index * BlockSize;
                counterBlocks[offset] = (byte)(lengthFieldLength - 1);
                Array.Copy(nonce, 0, counterBlocks, offset + 1, nonce.Length);

                int counter = index;
                for (int position = offset + 15; position > offset + 15 - lengthFieldLength; position--)
                {
                    counterBlocks[position] = (byte)counter;
                    counter >>= 8;
                }
            }

            aes.Mode = CipherMode.ECB;
            using (ICryptoTransform ecb = aes.CreateEncryptor())
            {
                return ecb.TransformFinalBlock(counterBlocks, 0, counterBlocks.Length);
            }
        }

        private static void WriteB0Block(byte[] buffer, byte[] nonce, bool hasAssociatedData, int signatureLength, int messageLength)
        {
            int lengthFieldLength = 15 - nonce.Length;
            byte flags = (byte)(lengthFieldLength - 1); // L'
            flags |= (byte)(((signatureLength - 2) / 2) << 3); // M'
            if (hasAssociatedData)
            {
                flags |= 0x40;
            }

            buffer[0] = flags;
            Array.Copy(nonce, 0, buffer, 1, nonce.Length);

            int length = messageLength;
            for (int index = 15; index > 15 - lengthFieldLength; index--)
            {
                buffer[index] = (byte)length;
                length >>= 8;
            }
        }

        private static byte[] Xor(byte[] data, byte[] keyStream, int keyStreamOffset)
        {
            byte[] result = new byte[data.Length];
            for (int index = 0; index < data.Length; index++)
            {
                result[index] = (byte)(data[index] ^ keyStream[keyStreamOffset + index]);
            }
            return result;
        }

        private static int PadToBlock(int length)
        {
            return (length + BlockSize - 1) / BlockSize * BlockSize;
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
    }
}
