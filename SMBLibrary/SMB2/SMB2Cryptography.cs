/* Copyright (C) 2020-2026 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Security.Cryptography;
using Utilities;
using AesCcm = Utilities.AesCcm;

namespace SMBLibrary.SMB2
{
    internal class SMB2Cryptography
    {
        private const int AesCcmNonceLength = 11;
        private const int AesGcmNonceLength = 12;

        public static byte[] CalculateSignature(byte[] signingKey, SMB2Dialect dialect, byte[] buffer, int offset, int paddedLength)
        {
            byte[] hash;
            if (dialect == SMB2Dialect.SMB202 || dialect == SMB2Dialect.SMB210)
            {
                hash = new HMACSHA256(signingKey).ComputeHash(buffer, offset, paddedLength);
            }
            else
            {
                hash = AesCmac.CalculateAesCmac(signingKey, buffer, offset, paddedLength);
            }

            // [MS-SMB2] The first 16 bytes of the hash MUST be copied into the 16-byte signature field of the SMB2 Header.
            return ByteReader.ReadBytes(hash, 0, SMB2Header.SignatureLength);
        }

        public static bool VerifySignature(byte[] messageBytes, SMB2Dialect dialect, byte[] signingKey)
        {
            byte[] signature = ByteReader.ReadBytes(messageBytes, SMB2Header.SignatureOffset, SMB2Header.SignatureLength);
            Array.Clear(messageBytes, SMB2Header.SignatureOffset, SMB2Header.SignatureLength);
            byte[] expectedSignature = CalculateSignature(signingKey, dialect, messageBytes, 0, messageBytes.Length);
            return ByteUtils.AreByteArraysEqual(signature, expectedSignature);
        }

        public static byte[] GenerateSigningKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue)
        {
            if (dialect == SMB2Dialect.SMB202 || dialect == SMB2Dialect.SMB210)
            {
                return sessionKey;
            }

            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException("preauthIntegrityHashValue");
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBSigningKey" : "SMB2AESCMAC";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("SmbSign");

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, 128);
        }

        public static byte[] GenerateClientEncryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue)
        {
            return GenerateClientEncryptionKey(sessionKey, dialect, preauthIntegrityHashValue, CipherAlgorithm.Aes128Ccm);
        }

        /// <param name="cipher">Connection.CipherId; SMB 3.0 and 3.0.2 always use AES-128-CCM</param>
        public static byte[] GenerateClientEncryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue, CipherAlgorithm cipher)
        {
            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException("preauthIntegrityHashValue");
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBC2SCipherKey" : "SMB2AESCCM";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("ServerIn ");

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, GetKeyLengthInBits(dialect, cipher));
        }

        public static byte[] GenerateClientDecryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue)
        {
            return GenerateClientDecryptionKey(sessionKey, dialect, preauthIntegrityHashValue, CipherAlgorithm.Aes128Ccm);
        }

        /// <param name="cipher">Connection.CipherId; SMB 3.0 and 3.0.2 always use AES-128-CCM</param>
        public static byte[] GenerateClientDecryptionKey(byte[] sessionKey, SMB2Dialect dialect, byte[] preauthIntegrityHashValue, CipherAlgorithm cipher)
        {
            if (dialect == SMB2Dialect.SMB311 && preauthIntegrityHashValue == null)
            {
                throw new ArgumentNullException("preauthIntegrityHashValue");
            }

            string labelString = (dialect == SMB2Dialect.SMB311) ? "SMBS2CCipherKey" : "SMB2AESCCM";
            byte[] label = GetNullTerminatedAnsiString(labelString);
            byte[] context = (dialect == SMB2Dialect.SMB311) ? preauthIntegrityHashValue : GetNullTerminatedAnsiString("ServerOut");

            HMACSHA256 hmac = new HMACSHA256(sessionKey);
            return SP800_1008.DeriveKey(hmac, label, context, GetKeyLengthInBits(dialect, cipher));
        }

        /// <summary>
        /// [MS-SMB2] 3.2.5.3.1 AES-256-CCM and AES-256-GCM (SMB 3.1.1 only) use 256 bit keys, the other ciphers 128 bit.
        /// The session key is the full session key; NTLM session keys are 128 bit anyway.
        /// </summary>
        public static int GetKeyLengthInBits(SMB2Dialect dialect, CipherAlgorithm cipher)
        {
            if (dialect == SMB2Dialect.SMB311 && (cipher == CipherAlgorithm.Aes256Ccm || cipher == CipherAlgorithm.Aes256Gcm))
            {
                return 256;
            }
            return 128;
        }

        public static bool IsSupportedCipher(CipherAlgorithm cipher)
        {
            return cipher == CipherAlgorithm.Aes128Ccm || cipher == CipherAlgorithm.Aes128Gcm ||
                   cipher == CipherAlgorithm.Aes256Ccm || cipher == CipherAlgorithm.Aes256Gcm;
        }

        /// <summary>
        /// Encrypt message (AES-128-CCM) and prefix with SMB2 TransformHeader
        /// </summary>
        public static byte[] TransformMessage(byte[] key, byte[] message, ulong sessionID)
        {
            return TransformMessage(key, message, sessionID, CipherAlgorithm.Aes128Ccm);
        }

        /// <summary>
        /// Encrypt message and prefix with SMB2 TransformHeader
        /// </summary>
        public static byte[] TransformMessage(byte[] key, byte[] message, ulong sessionID, CipherAlgorithm cipher)
        {
            byte[] nonce = GenerateNonce(cipher);
            byte[] signature;
            byte[] encryptedMessage = EncryptMessage(key, nonce, message, sessionID, cipher, out signature);
            SMB2TransformHeader transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
            transformHeader.Signature = signature;

            byte[] buffer = new byte[SMB2TransformHeader.Length + message.Length];
            transformHeader.WriteBytes(buffer, 0);
            ByteWriter.WriteBytes(buffer, SMB2TransformHeader.Length, encryptedMessage);
            return buffer;
        }

        public static byte[] EncryptMessage(byte[] key, byte[] nonce, byte[] message, ulong sessionID, out byte[] signature)
        {
            return EncryptMessage(key, nonce, message, sessionID, CipherAlgorithm.Aes128Ccm, out signature);
        }

        public static byte[] EncryptMessage(byte[] key, byte[] nonce, byte[] message, ulong sessionID, CipherAlgorithm cipher, out byte[] signature)
        {
            SMB2TransformHeader transformHeader = CreateTransformHeader(nonce, message.Length, sessionID);
            byte[] associatedData = transformHeader.GetAssociatedData();
            if (IsGcm(cipher))
            {
                return AesGcmCipher.Encrypt(key, nonce, message, associatedData, out signature);
            }
            return AesCcm.Encrypt(key, nonce, message, associatedData, SMB2TransformHeader.SignatureLength, out signature);
        }

        public static byte[] DecryptMessage(byte[] key, SMB2TransformHeader transformHeader, byte[] encryptedMessage)
        {
            return DecryptMessage(key, transformHeader, encryptedMessage, CipherAlgorithm.Aes128Ccm);
        }

        /// <remarks>The transform header does not name the cipher (SMB 3.1.1): it is the one negotiated for the connection</remarks>
        /// <exception cref="CryptographicException">The message was changed or the key is wrong</exception>
        public static byte[] DecryptMessage(byte[] key, SMB2TransformHeader transformHeader, byte[] encryptedMessage, CipherAlgorithm cipher)
        {
            byte[] associatedData = transformHeader.GetAssociatedData();
            byte[] nonce = ByteReader.ReadBytes(transformHeader.Nonce, 0, GetNonceLength(cipher));
            if (IsGcm(cipher))
            {
                return AesGcmCipher.DecryptAndAuthenticate(key, nonce, encryptedMessage, associatedData, transformHeader.Signature);
            }
            return AesCcm.DecryptAndAuthenticate(key, nonce, encryptedMessage, associatedData, transformHeader.Signature);
        }

        private static bool IsGcm(CipherAlgorithm cipher)
        {
            return cipher == CipherAlgorithm.Aes128Gcm || cipher == CipherAlgorithm.Aes256Gcm;
        }

        // [MS-SMB2] 2.2.41 AES-CCM uses the first 11 bytes of the 16 byte nonce field, AES-GCM the first 12
        private static int GetNonceLength(CipherAlgorithm cipher)
        {
            if (!IsSupportedCipher(cipher))
            {
                throw new NotSupportedException($"Cipher {cipher} is not supported");
            }
            return IsGcm(cipher) ? AesGcmNonceLength : AesCcmNonceLength;
        }

        public static byte[] ComputeHash(HashAlgorithm hashAlgorithm, byte[] buffer)
        {
            if (hashAlgorithm == HashAlgorithm.SHA512)
            {
                return SHA512.Create().ComputeHash(buffer);
            }
            else
            {
                throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported");
            }
        }

        private static SMB2TransformHeader CreateTransformHeader(byte[] nonce, int originalMessageLength, ulong sessionID)
        {
            byte[] nonceWithPadding = new byte[SMB2TransformHeader.NonceLength];
            Array.Copy(nonce, nonceWithPadding, nonce.Length);

            SMB2TransformHeader transformHeader = new SMB2TransformHeader();
            transformHeader.Nonce = nonceWithPadding;
            transformHeader.OriginalMessageSize = (uint)originalMessageLength;
            transformHeader.Flags = SMB2TransformHeaderFlags.Encrypted;
            transformHeader.SessionId = sessionID;

            return transformHeader;
        }

        private static byte[] GenerateNonce(CipherAlgorithm cipher)
        {
            byte[] nonce = new byte[GetNonceLength(cipher)];
            SecureRandom.GetBytes(nonce);
            return nonce;
        }

        private static byte[] GetNullTerminatedAnsiString(string value)
        {
            byte[] result = new byte[value.Length + 1];
            ByteWriter.WriteNullTerminatedAnsiString(result, 0, value);
            return result;
        }
    }
}
