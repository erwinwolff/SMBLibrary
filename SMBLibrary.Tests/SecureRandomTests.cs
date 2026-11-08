/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Tests
{
    [TestClass]
    public class SecureRandomTests
    {
        [TestMethod]
        public void TestConsecutiveBuffersDiffer()
        {
            // With new Random() on .NET Framework, buffers created within one clock tick were identical
            HashSet<string> seen = new HashSet<string>();
            for (int index = 0; index < 1000; index++)
            {
                Assert.IsTrue(seen.Add(Convert.ToBase64String(SecureRandom.GetBytes(16))));
            }
        }

        [TestMethod]
        public void TestEncryptionNoncesAreUnique()
        {
            // AES-CCM breaks when a nonce is used twice with the same key; messages are encrypted in quick succession
            byte[] key = SecureRandom.GetBytes(16);
            byte[] message = new byte[64];
            HashSet<string> nonces = new HashSet<string>();

            for (int index = 0; index < 1000; index++)
            {
                byte[] transformed = SMB2Cryptography.TransformMessage(key, message, 0x1122334455667788);
                SMB2TransformHeader header = new SMB2TransformHeader(transformed, 0);
                Assert.IsTrue(nonces.Add(Convert.ToBase64String(header.Nonce)));
            }
        }
    }
}
