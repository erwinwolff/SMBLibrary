/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Tests
{
    [TestClass]
    public class SMB2CipherTests
    {
        private static readonly CipherAlgorithm[] AllCiphers = { CipherAlgorithm.Aes128Ccm, CipherAlgorithm.Aes128Gcm, CipherAlgorithm.Aes256Ccm, CipherAlgorithm.Aes256Gcm };

        [TestMethod]
        public void TestAesGcmNistTestCase4()
        {
            // "The Galois/Counter Mode of Operation (GCM)", McGrew and Viega, test case 4 (AES-128, 96 bit IV, associated data)
            byte[] key = Hex("feffe9928665731c6d6a8f9467308308");
            byte[] nonce = Hex("cafebabefacedbaddecaf888");
            byte[] plainText = Hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
            byte[] associatedData = Hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
            byte[] expectedCipherText = Hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091");
            byte[] expectedTag = Hex("5bc94fbc3221a5db94fae95ae7121a47");

            byte[] tag;
            byte[] cipherText = AesGcmManaged.Encrypt(key, nonce, plainText, associatedData, out tag);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedCipherText, cipherText));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedTag, tag));

            byte[] decrypted = AesGcmManaged.DecryptAndAuthenticate(key, nonce, cipherText, associatedData, tag);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(plainText, decrypted));

            cipherText = AesGcmCipher.Encrypt(key, nonce, plainText, associatedData, out tag);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedCipherText, cipherText));
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expectedTag, tag));
        }

#if NET
        [TestMethod]
        public void TestManagedAesGcmMatchesPlatform()
        {
            // The managed implementation only runs on .NET Framework; here it is compared with the AesGcm class of .NET
            Random random = new Random(1234);
            int[] lengths = { 0, 1, 15, 16, 17, 31, 32, 33, 100, 255, 4096, 65536 + 7, 1048576 };
            foreach (int keyLength in new[] { 16, 32 })
            {
                foreach (int length in lengths)
                {
                    byte[] key = RandomBytes(random, keyLength);
                    byte[] nonce = RandomBytes(random, AesGcmCipher.NonceLength);
                    byte[] data = RandomBytes(random, length);
                    byte[] associatedData = RandomBytes(random, 32);

                    byte[] managedTag;
                    byte[] managed = AesGcmManaged.Encrypt(key, nonce, data, associatedData, out managedTag);

                    byte[] platform = new byte[length];
                    byte[] platformTag = new byte[AesGcmCipher.TagLength];
                    using (System.Security.Cryptography.AesGcm aesGcm = new System.Security.Cryptography.AesGcm(key, AesGcmCipher.TagLength))
                    {
                        aesGcm.Encrypt(nonce, data, platform, platformTag, associatedData);
                    }

                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(platform, managed), "cipher text, key " + keyLength + ", length " + length);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(platformTag, managedTag), "tag, key " + keyLength + ", length " + length);
                    Assert.IsTrue(ByteUtils.AreByteArraysEqual(data, AesGcmManaged.DecryptAndAuthenticate(key, nonce, platform, associatedData, platformTag)));
                }
            }
        }
#endif

        [TestMethod]
        public void TestManagedAesGcmRejectsTampering()
        {
            byte[] key = SecureRandom.GetBytes(32);
            byte[] nonce = SecureRandom.GetBytes(AesGcmCipher.NonceLength);
            byte[] data = SecureRandom.GetBytes(100);
            byte[] associatedData = SecureRandom.GetBytes(32);

            byte[] tag;
            byte[] cipherText = AesGcmManaged.Encrypt(key, nonce, data, associatedData, out tag);

            byte[] changedCipherText = (byte[])cipherText.Clone();
            changedCipherText[50] ^= 1;
            Assert.IsTrue(Throws(() => AesGcmManaged.DecryptAndAuthenticate(key, nonce, changedCipherText, associatedData, tag)));

            byte[] changedAssociatedData = (byte[])associatedData.Clone();
            changedAssociatedData[0] ^= 1;
            Assert.IsTrue(Throws(() => AesGcmManaged.DecryptAndAuthenticate(key, nonce, cipherText, changedAssociatedData, tag)));
        }

        [TestMethod]
        public void TestKeyLengths()
        {
            byte[] sessionKey = SecureRandom.GetBytes(16);
            byte[] preauthIntegrityHashValue = SecureRandom.GetBytes(64);

            Assert.AreEqual(16, SMB2Cryptography.GenerateClientEncryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, CipherAlgorithm.Aes128Ccm).Length);
            Assert.AreEqual(16, SMB2Cryptography.GenerateClientEncryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, CipherAlgorithm.Aes128Gcm).Length);
            Assert.AreEqual(32, SMB2Cryptography.GenerateClientEncryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, CipherAlgorithm.Aes256Ccm).Length);
            Assert.AreEqual(32, SMB2Cryptography.GenerateClientDecryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, CipherAlgorithm.Aes256Gcm).Length);

            // [MS-SMB2] The first 128 bits of the 256 bit key are not the 128 bit key: L is part of the KDF input
            byte[] key128 = SMB2Cryptography.GenerateClientEncryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, CipherAlgorithm.Aes128Gcm);
            byte[] key256 = SMB2Cryptography.GenerateClientEncryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, CipherAlgorithm.Aes256Gcm);
            Assert.IsFalse(ByteUtils.AreByteArraysEqual(key128, ByteReader.ReadBytes(key256, 0, 16)));
        }

        [TestMethod]
        public void TestTransformRoundTripForEveryCipher()
        {
            byte[] sessionKey = SecureRandom.GetBytes(16);
            byte[] preauthIntegrityHashValue = SecureRandom.GetBytes(64);
            byte[] message = SecureRandom.GetBytes(1000);
            ulong sessionID = 0x0000040000000005;

            foreach (CipherAlgorithm cipher in AllCiphers)
            {
                byte[] key = SMB2Cryptography.GenerateClientEncryptionKey(sessionKey, SMB2Dialect.SMB311, preauthIntegrityHashValue, cipher);
                byte[] transformed = SMB2Cryptography.TransformMessage(key, message, sessionID, cipher);

                SMB2TransformHeader header = new SMB2TransformHeader(transformed, 0);
                Assert.AreEqual((uint)message.Length, header.OriginalMessageSize);
                Assert.AreEqual(sessionID, header.SessionId);

                byte[] encrypted = ByteReader.ReadBytes(transformed, SMB2TransformHeader.Length, (int)header.OriginalMessageSize);
                Assert.IsFalse(ByteUtils.AreByteArraysEqual(message, encrypted), cipher.ToString());
                Assert.IsTrue(ByteUtils.AreByteArraysEqual(message, SMB2Cryptography.DecryptMessage(key, header, encrypted, cipher)), cipher.ToString());

                encrypted[10] ^= 1;
                Assert.IsTrue(Throws(() => SMB2Cryptography.DecryptMessage(key, header, encrypted, cipher)), cipher.ToString());
            }
        }

        [TestMethod]
        public void TestGcmNonceLength()
        {
            // AES-GCM uses 12 of the 16 nonce bytes of the transform header, AES-CCM 11; the rest stays zero
            byte[] key = SecureRandom.GetBytes(16);
            for (int index = 0; index < 50; index++)
            {
                SMB2TransformHeader gcm = new SMB2TransformHeader(SMB2Cryptography.TransformMessage(key, new byte[16], 1, CipherAlgorithm.Aes128Gcm), 0);
                Assert.IsTrue(IsZero(gcm.Nonce, 12));
                SMB2TransformHeader ccm = new SMB2TransformHeader(SMB2Cryptography.TransformMessage(key, new byte[16], 1, CipherAlgorithm.Aes128Ccm), 0);
                Assert.IsTrue(IsZero(ccm.Nonce, 11));
            }
        }

        [TestMethod]
        public void TestEncryptionCapabilitiesRoundTrip()
        {
            EncryptionCapabilities capabilities = new EncryptionCapabilities();
            capabilities.Ciphers.AddRange(AllCiphers);
            List<NegotiateContext> list = new List<NegotiateContext> { capabilities };

            byte[] buffer = new byte[NegotiateContext.GetNegotiateContextListLength(list)];
            NegotiateContext.WriteNegotiateContextList(buffer, 0, list);
            List<NegotiateContext> read = NegotiateContext.ReadNegotiateContextList(buffer, 0, 1);

            EncryptionCapabilities parsed = read[0] as EncryptionCapabilities;
            Assert.IsNotNull(parsed);
            Assert.AreEqual(AllCiphers.Length, parsed.Ciphers.Count);
            for (int index = 0; index < AllCiphers.Length; index++)
            {
                Assert.AreEqual(AllCiphers[index], parsed.Ciphers[index]);
            }
        }

        private static bool Throws(Action action)
        {
            try
            {
                action();
                return false;
            }
            catch (CryptographicException)
            {
                return true;
            }
        }

        private static bool IsZero(byte[] buffer, int from)
        {
            for (int index = from; index < buffer.Length; index++)
            {
                if (buffer[index] != 0)
                {
                    return false;
                }
            }
            return true;
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
