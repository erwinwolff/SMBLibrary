/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Utilities;

namespace SMBLibrary.Tests
{
    /// <summary>
    /// The accelerated paths must give the same results as before: RFC test vectors, and the managed implementations
    /// (used on .NET Framework) against the platform implementations of .NET
    /// </summary>
    [TestClass]
    public class HardwareAccelerationTests
    {
        private static readonly byte[] Rfc4493Key = Hex("2b7e151628aed2a6abf7158809cf4f3c");
        private static readonly byte[] Rfc4493Message = Hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");

        [TestMethod]
        public void TestAesCmacRfc4493()
        {
            // RFC 4493 4. Test Vectors: empty, one block, partial last block (40 bytes), four blocks
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(Hex("bb1d6929e95937287fa37d129b756746"), AesCmac.CalculateAesCmac(Rfc4493Key, new byte[0])));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(Hex("070a16b46b4d4144f79bdd9dd04a287c"), AesCmac.CalculateAesCmac(Rfc4493Key, Rfc4493Message, 0, 16)));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(Hex("dfa66747de9ae63030ca32611497c827"), AesCmac.CalculateAesCmac(Rfc4493Key, Rfc4493Message, 0, 40)));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(Hex("51f0bebf7e3b9d92fc49741779363cfe"), AesCmac.CalculateAesCmac(Rfc4493Key, Rfc4493Message, 0, 64)));
        }

        [TestMethod]
        public void TestAesCmacOffsetAndLargeMessage()
        {
            // A message inside a larger buffer (compound chain) and messages larger than the internal chunk size
            Random random = new Random(7);
            byte[] key = RandomBytes(random, 16);
            foreach (int length in new[] { 1, 15, 16, 17, 65536, 65536 + 16, 200000 })
            {
                byte[] message = RandomBytes(random, length);
                byte[] buffer = new byte[length + 100];
                Array.Copy(message, 0, buffer, 37, length);
                byte[] alone = AesCmac.CalculateAesCmac(key, message);
                Assert.IsTrue(ByteUtils.AreByteArraysEqual(alone, AesCmac.CalculateAesCmac(key, buffer, 37, length)), "length " + length);
                Assert.IsTrue(ByteUtils.AreByteArraysEqual(alone, ReferenceCmac(key, message)), "reference, length " + length);
            }
        }

        [TestMethod]
        public void TestAesCcmManagedRfc3610()
        {
            // RFC 3610 packet vector #1, through the managed implementation directly
            byte[] key = Hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
            byte[] nonce = Hex("00000003020100a0a1a2a3a4a5");
            byte[] data = Hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
            byte[] associatedData = Hex("0001020304050607");

            byte[] signature;
            byte[] encrypted = AesCcmManaged.Encrypt(key, nonce, data, associatedData, 8, out signature);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(Hex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"), encrypted));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(Hex("17e8d12cfdf926e0"), signature));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, AesCcmManaged.DecryptAndAuthenticate(key, nonce, encrypted, associatedData, signature)));
        }

#if NET
        [TestMethod]
        public void TestManagedAesCcmMatchesPlatform()
        {
            Random random = new Random(42);
            foreach (int keyLength in new[] { 16, 32 })
            {
                foreach (int length in new[] { 0, 1, 15, 16, 17, 100, 4096, 65536 + 5, 1048576 })
                {
                    byte[] key = RandomBytes(random, keyLength);
                    byte[] nonce = RandomBytes(random, 11);
                    byte[] data = RandomBytes(random, length);
                    byte[] associatedData = RandomBytes(random, 32);

                    byte[] managedSignature;
                    byte[] managed = AesCcmManaged.Encrypt(key, nonce, data, associatedData, 16, out managedSignature);
                    byte[] platformSignature;
                    byte[] platform = AesCcm.Encrypt(key, nonce, data, associatedData, 16, out platformSignature);

                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(platform, managed), "cipher text, key " + keyLength + ", length " + length);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(platformSignature, managedSignature), "signature, key " + keyLength + ", length " + length);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, AesCcmManaged.DecryptAndAuthenticate(key, nonce, platform, associatedData, platformSignature)));
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, AesCcm.DecryptAndAuthenticate(key, nonce, managed, associatedData, managedSignature)));
                }
            }
        }
#endif

        [TestMethod]
        public void TestAesCcmManagedRejectsTampering()
        {
            byte[] key = SecureRandom.GetBytes(16);
            byte[] nonce = SecureRandom.GetBytes(11);
            byte[] data = SecureRandom.GetBytes(100);
            byte[] associatedData = SecureRandom.GetBytes(32);

            byte[] signature;
            byte[] encrypted = AesCcmManaged.Encrypt(key, nonce, data, associatedData, 16, out signature);
            encrypted[3] ^= 1;
            bool thrown = false;
            try
            {
                AesCcmManaged.DecryptAndAuthenticate(key, nonce, encrypted, associatedData, signature);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                thrown = true;
            }
            Assert.IsTrue(thrown);
        }

        // Plain CMAC from RFC 4493 2.4, block by block, as an independent reference
        [TestMethod]
        public void TestHardwareAeadMatchesManaged()
        {
            // The public classes use the hardware path of the platform (.NET 10: AesGcm / AesCcm, .NET Framework:
            // Windows CNG); every result must equal the managed implementation, also across the two paths
            Random random = new Random(4321);
            int[] lengths = { 0, 1, 15, 16, 17, 100, 4096, 65536 + 3, 1048576 };
            foreach (int keyLength in new[] { 16, 32 })
            {
                foreach (int length in lengths)
                {
                    byte[] key = RandomBytes(random, keyLength);
                    byte[] data = RandomBytes(random, length);
                    byte[] associatedData = RandomBytes(random, 32);
                    string context = "key " + keyLength + ", length " + length;

                    byte[] gcmNonce = RandomBytes(random, AesGcmCipher.NonceLength);
                    byte[] managedTag;
                    byte[] managed = AesGcmManaged.Encrypt(key, gcmNonce, data, associatedData, out managedTag);
                    byte[] tag;
                    byte[] hardware = AesGcmCipher.Encrypt(key, gcmNonce, data, associatedData, out tag);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(managed, hardware), "GCM " + context);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(managedTag, tag), "GCM tag " + context);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, AesGcmCipher.DecryptAndAuthenticate(key, gcmNonce, managed, associatedData, managedTag)), "GCM decrypt " + context);

                    byte[] ccmNonce = RandomBytes(random, 11);
                    byte[] managedSignature;
                    managed = AesCcmManaged.Encrypt(key, ccmNonce, data, associatedData, 16, out managedSignature);
                    byte[] signature;
                    hardware = AesCcm.Encrypt(key, ccmNonce, data, associatedData, 16, out signature);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(managed, hardware), "CCM " + context);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(managedSignature, signature), "CCM tag " + context);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, AesCcm.DecryptAndAuthenticate(key, ccmNonce, managed, associatedData, managedSignature)), "CCM decrypt " + context);

                    // GMAC over a slice of a larger buffer
                    byte[] buffer = RandomBytes(random, length + 20);
                    byte[] slice = ByteReader.ReadBytes(buffer, 7, length);
                    AesGcmManaged.Encrypt(key, gcmNonce, new byte[0], slice, out managedTag);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(managedTag, AesGcmCipher.ComputeGmac(key, gcmNonce, buffer, 7, length)), "GMAC " + context);
                }
            }
        }

        [TestMethod]
        public void TestHardwareAeadRejectsTampering()
        {
            byte[] key = SecureRandom.GetBytes(16);
            byte[] data = SecureRandom.GetBytes(1000);
            byte[] associatedData = SecureRandom.GetBytes(32);

            byte[] gcmNonce = SecureRandom.GetBytes(AesGcmCipher.NonceLength);
            byte[] tag;
            byte[] encrypted = AesGcmCipher.Encrypt(key, gcmNonce, data, associatedData, out tag);
            encrypted[500] ^= 1;
            Assert.IsTrue(Throws(() => AesGcmCipher.DecryptAndAuthenticate(key, gcmNonce, encrypted, associatedData, tag)), "GCM");

            byte[] ccmNonce = SecureRandom.GetBytes(11);
            byte[] signature;
            encrypted = AesCcm.Encrypt(key, ccmNonce, data, associatedData, 16, out signature);
            signature[0] ^= 1;
            Assert.IsTrue(Throws(() => AesCcm.DecryptAndAuthenticate(key, ccmNonce, encrypted, associatedData, signature)), "CCM");
        }

        private static bool Throws(Action action)
        {
            try
            {
                action();
                return false;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return true;
            }
        }

        private static byte[] ReferenceCmac(byte[] key, byte[] message)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.Key = key;
                aes.Mode = System.Security.Cryptography.CipherMode.ECB;
                aes.Padding = System.Security.Cryptography.PaddingMode.None;
                System.Security.Cryptography.ICryptoTransform ecb = aes.CreateEncryptor();

                byte[] l = ecb.TransformFinalBlock(new byte[16], 0, 16);
                byte[] k1 = ShiftLeft(l);
                if ((l[0] & 0x80) != 0) k1[15] ^= 0x87;
                byte[] k2 = ShiftLeft(k1);
                if ((k1[0] & 0x80) != 0) k2[15] ^= 0x87;

                int blocks = Math.Max(1, (message.Length + 15) / 16);
                bool complete = message.Length > 0 && message.Length % 16 == 0;
                byte[] x = new byte[16];
                for (int block = 0; block < blocks; block++)
                {
                    byte[] m = new byte[16];
                    int length = Math.Min(16, message.Length - block * 16);
                    if (length > 0) Array.Copy(message, block * 16, m, 0, length);
                    if (block == blocks - 1)
                    {
                        if (!complete) m[Math.Max(length, 0)] = 0x80;
                        byte[] k = complete ? k1 : k2;
                        for (int i = 0; i < 16; i++) m[i] ^= k[i];
                    }
                    for (int i = 0; i < 16; i++) x[i] ^= m[i];
                    x = ecb.TransformFinalBlock(x, 0, 16);
                }
                return x;
            }
        }

        private static byte[] ShiftLeft(byte[] value)
        {
            byte[] result = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                result[i] = (byte)(value[i] << 1);
                if (i < 15) result[i] |= (byte)(value[i + 1] >> 7);
            }
            return result;
        }

        private static byte[] RandomBytes(Random random, int length)
        {
            byte[] result = new byte[length];
            random.NextBytes(result);
            return result;
        }

        private static byte[] Hex(string hex)
        {
            byte[] result = new byte[hex.Length / 2];
            for (int index = 0; index < result.Length; index++)
            {
                result[index] = Convert.ToByte(hex.Substring(index * 2, 2), 16);
            }
            return result;
        }
    }
}
