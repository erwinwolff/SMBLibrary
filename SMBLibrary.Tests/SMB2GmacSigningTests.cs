/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Tests
{
    [TestClass]
    public class SMB2GmacSigningTests
    {
        [TestMethod]
        public void TestGmacIsGcmTagOverMessage()
        {
            // [MS-SMB2] 3.1.4.1 / RFC 4543: GMAC is AES-GCM without plain text and the whole message as associated data.
            // Nonce: MessageId (8 bytes), then 4 bytes with bit 0 = sent by the server and bit 1 = CANCEL request.
            byte[] key = SecureRandom.GetBytes(16);
            byte[] message = BuildMessage(SMB2CommandName.Read, 0x0102030405060708, false);

            byte[] expectedNonce = new byte[] { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00 };
            byte[] expected;
            AesGcmCipher.Encrypt(key, expectedNonce, new byte[0], message, out expected);

            byte[] signature = SMB2Cryptography.CalculateSignature(key, SigningAlgorithm.AesGmac, message, 0, message.Length);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expected, signature));
        }

        [TestMethod]
        public void TestGmacNonceRoleAndCancelBits()
        {
            byte[] key = SecureRandom.GetBytes(16);

            byte[] response = BuildMessage(SMB2CommandName.Read, 42, true);
            byte[] responseNonce = new byte[] { 42, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00 };
            byte[] expected;
            AesGcmCipher.Encrypt(key, responseNonce, new byte[0], response, out expected);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expected, SMB2Cryptography.CalculateSignature(key, SigningAlgorithm.AesGmac, response, 0, response.Length)));

            byte[] cancel = BuildMessage(SMB2CommandName.Cancel, 42, false);
            byte[] cancelNonce = new byte[] { 42, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x00, 0x00 };
            AesGcmCipher.Encrypt(key, cancelNonce, new byte[0], cancel, out expected);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expected, SMB2Cryptography.CalculateSignature(key, SigningAlgorithm.AesGmac, cancel, 0, cancel.Length)));
        }

        [TestMethod]
        public void TestGmacSignAndVerify()
        {
            byte[] key = SecureRandom.GetBytes(16);
            byte[] message = BuildMessage(SMB2CommandName.Write, 7, true);

            byte[] signature = SMB2Cryptography.CalculateSignature(key, SigningAlgorithm.AesGmac, message, 0, message.Length);
            ByteWriter.WriteBytes(message, SMB2Header.SignatureOffset, signature);
            Assert.IsTrue(SMB2Cryptography.VerifySignature((byte[])message.Clone(), SigningAlgorithm.AesGmac, key));

            byte[] changed = (byte[])message.Clone();
            changed[100] ^= 1;
            Assert.IsFalse(SMB2Cryptography.VerifySignature(changed, SigningAlgorithm.AesGmac, key));

            // The MessageId is part of the nonce: a replayed signature with another MessageId fails
            byte[] otherMessageId = (byte[])message.Clone();
            otherMessageId[24] ^= 1;
            Assert.IsFalse(SMB2Cryptography.VerifySignature(otherMessageId, SigningAlgorithm.AesGmac, key));
        }

        [TestMethod]
        public void TestPaddedCompoundMessage()
        {
            // A message inside a compound chain is signed from its own header (offset) over its padded length
            byte[] key = SecureRandom.GetBytes(16);
            byte[] first = BuildMessage(SMB2CommandName.Create, 10, false);
            byte[] second = BuildMessage(SMB2CommandName.Read, 11, false);
            byte[] chain = ByteUtils.Concatenate(first, second);

            byte[] expected = SMB2Cryptography.CalculateSignature(key, SigningAlgorithm.AesGmac, second, 0, second.Length);
            byte[] actual = SMB2Cryptography.CalculateSignature(key, SigningAlgorithm.AesGmac, chain, first.Length, second.Length);
            Assert.IsTrue(ByteUtils.AreByteArraysEqual(expected, actual));
        }

        [TestMethod]
        public void TestDialectDefaults()
        {
            Assert.AreEqual(SigningAlgorithm.HmacSha256, SMB2Cryptography.GetDefaultSigningAlgorithm(SMB2Dialect.SMB210));
            Assert.AreEqual(SigningAlgorithm.AesCmac, SMB2Cryptography.GetDefaultSigningAlgorithm(SMB2Dialect.SMB300));
            Assert.AreEqual(SigningAlgorithm.AesCmac, SMB2Cryptography.GetDefaultSigningAlgorithm(SMB2Dialect.SMB311));
        }

        [TestMethod]
        public void TestSigningCapabilitiesRoundTrip()
        {
            SigningCapabilities capabilities = new SigningCapabilities();
            capabilities.SigningAlgorithms.Add(SigningAlgorithm.AesGmac);
            capabilities.SigningAlgorithms.Add(SigningAlgorithm.AesCmac);
            List<NegotiateContext> list = new List<NegotiateContext> { new EncryptionCapabilities(), capabilities };

            byte[] buffer = new byte[NegotiateContext.GetNegotiateContextListLength(list)];
            NegotiateContext.WriteNegotiateContextList(buffer, 0, list);
            List<NegotiateContext> read = NegotiateContext.ReadNegotiateContextList(buffer, 0, 2);

            SigningCapabilities parsed = read[1] as SigningCapabilities;
            Assert.IsNotNull(parsed);
            Assert.AreEqual(2, parsed.SigningAlgorithms.Count);
            Assert.AreEqual(SigningAlgorithm.AesGmac, parsed.SigningAlgorithms[0]);
            Assert.AreEqual(SigningAlgorithm.AesCmac, parsed.SigningAlgorithms[1]);
        }

#if NET
        [TestMethod]
        public void TestManagedGmacMatchesPlatformForLargeMessages()
        {
            // Signing puts the whole message in the associated data, unlike encryption
            System.Random random = new System.Random(99);
            foreach (int length in new[] { 64, 65, 1000, 65536 + 3, 1048576 })
            {
                byte[] key = new byte[16];
                byte[] nonce = new byte[12];
                byte[] message = new byte[length];
                random.NextBytes(key);
                random.NextBytes(nonce);
                random.NextBytes(message);

                byte[] managed;
                AesGcmManaged.Encrypt(key, nonce, new byte[0], message, out managed);
                byte[] platform;
                AesGcmCipher.Encrypt(key, nonce, new byte[0], message, out platform);
                Assert.IsTrue(ByteUtils.AreByteArraysEqual(platform, managed), "length " + length);
            }
        }
#endif

        private static byte[] BuildMessage(SMB2CommandName command, ulong messageId, bool fromServer)
        {
            byte[] message = SecureRandom.GetBytes(SMB2Header.Length + 120);
            message[0] = 0xFE; message[1] = (byte)'S'; message[2] = (byte)'M'; message[3] = (byte)'B';
            LittleEndianWriter.WriteUInt16(message, 12, (ushort)command);
            LittleEndianWriter.WriteUInt32(message, 16, fromServer ? (uint)SMB2PacketHeaderFlags.ServerToRedir | (uint)SMB2PacketHeaderFlags.Signed : (uint)SMB2PacketHeaderFlags.Signed);
            LittleEndianWriter.WriteUInt64(message, 24, messageId);
            ByteWriter.WriteBytes(message, SMB2Header.SignatureOffset, new byte[SMB2Header.SignatureLength]);
            return message;
        }
    }
}
