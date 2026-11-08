/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
#if NETFRAMEWORK
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Utilities
{
    /// <summary>
    /// AES-GCM and AES-CCM through Windows CNG (bcrypt.dll) for .NET Framework, which has no managed AEAD classes.
    /// CNG uses AES-NI and PCLMULQDQ when the processor has them. .NET Framework 4.8.1 only runs on Windows 10 and
    /// later, where CNG always supports both chaining modes, so there is no managed fallback here.
    /// </summary>
    internal static class BCryptAead
    {
        private const string AesAlgorithm = "AES";
        private const string ChainingModeProperty = "ChainingMode";
        private const string ChainingModeGcm = "ChainingModeGCM";
        private const string ChainingModeCcm = "ChainingModeCCM";

        private const int StatusSuccess = 0;
        private const int StatusAuthTagMismatch = unchecked((int)0xC000A002);

        // Algorithm handles are thread safe and live for the lifetime of the process
        private static readonly Lazy<IntPtr> GcmAlgorithm = new Lazy<IntPtr>(() => OpenAlgorithm(ChainingModeGcm));
        private static readonly Lazy<IntPtr> CcmAlgorithm = new Lazy<IntPtr>(() => OpenAlgorithm(ChainingModeCcm));

        public static byte[] EncryptGcm(byte[] key, byte[] nonce, byte[] data, int offset, int length, byte[] associatedData, int tagLength, out byte[] tag)
        {
            return Encrypt(GcmAlgorithm.Value, key, nonce, data, offset, length, associatedData, 0, associatedData == null ? 0 : associatedData.Length, tagLength, out tag);
        }

        public static byte[] EncryptCcm(byte[] key, byte[] nonce, byte[] data, byte[] associatedData, int tagLength, out byte[] tag)
        {
            return Encrypt(CcmAlgorithm.Value, key, nonce, data, 0, data.Length, associatedData, 0, associatedData == null ? 0 : associatedData.Length, tagLength, out tag);
        }

        /// <summary>
        /// AES-GMAC: the GCM tag of the message passed as associated data, without copying it
        /// </summary>
        public static byte[] ComputeGmac(byte[] key, byte[] nonce, byte[] data, int offset, int length, int tagLength)
        {
            byte[] tag;
            Encrypt(GcmAlgorithm.Value, key, nonce, new byte[0], 0, 0, data, offset, length, tagLength, out tag);
            return tag;
        }

        /// <exception cref="CryptographicException">The data or the associated data was changed, or the key is wrong</exception>
        public static byte[] DecryptGcm(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] tag)
        {
            return Decrypt(GcmAlgorithm.Value, key, nonce, encryptedData, associatedData, tag);
        }

        /// <exception cref="CryptographicException">The data or the associated data was changed, or the key is wrong</exception>
        public static byte[] DecryptCcm(byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] tag)
        {
            return Decrypt(CcmAlgorithm.Value, key, nonce, encryptedData, associatedData, tag);
        }

        private static byte[] Encrypt(IntPtr algorithm, byte[] key, byte[] nonce, byte[] data, int offset, int length, byte[] associatedData, int associatedDataOffset, int associatedDataLength, int tagLength, out byte[] tag)
        {
            byte[] output = new byte[length];
            tag = new byte[tagLength];
            Transform(algorithm, true, key, nonce, data, offset, length, associatedData, associatedDataOffset, associatedDataLength, tag, output);
            return output;
        }

        private static byte[] Decrypt(IntPtr algorithm, byte[] key, byte[] nonce, byte[] encryptedData, byte[] associatedData, byte[] tag)
        {
            byte[] output = new byte[encryptedData.Length];
            Transform(algorithm, false, key, nonce, encryptedData, 0, encryptedData.Length, associatedData, 0, associatedData == null ? 0 : associatedData.Length, tag, output);
            return output;
        }

        private static void Transform(IntPtr algorithm, bool encrypt, byte[] key, byte[] nonce, byte[] input, int inputOffset, int inputLength, byte[] associatedData, int associatedDataOffset, int associatedDataLength, byte[] tag, byte[] output)
        {
            IntPtr keyHandle;
            CheckStatus(BCryptGenerateSymmetricKey(algorithm, out keyHandle, IntPtr.Zero, 0, key, key.Length, 0));

            GCHandle inputHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
            GCHandle outputHandle = GCHandle.Alloc(output, GCHandleType.Pinned);
            GCHandle nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            GCHandle associatedDataHandle = associatedDataLength > 0 ? GCHandle.Alloc(associatedData, GCHandleType.Pinned) : default(GCHandle);
            try
            {
                AuthenticatedCipherModeInfo info = new AuthenticatedCipherModeInfo();
                info.cbSize = Marshal.SizeOf(typeof(AuthenticatedCipherModeInfo));
                info.dwInfoVersion = 1; // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION
                info.pbNonce = nonceHandle.AddrOfPinnedObject();
                info.cbNonce = nonce.Length;
                info.pbTag = tagHandle.AddrOfPinnedObject();
                info.cbTag = tag.Length;
                if (associatedDataLength > 0)
                {
                    info.pbAuthData = IntPtr.Add(associatedDataHandle.AddrOfPinnedObject(), associatedDataOffset);
                    info.cbAuthData = associatedDataLength;
                }

                // Slices of the pinned arrays: the input is never copied
                IntPtr inputPointer = inputLength > 0 ? IntPtr.Add(inputHandle.AddrOfPinnedObject(), inputOffset) : IntPtr.Zero;
                IntPtr outputPointer = output.Length > 0 ? outputHandle.AddrOfPinnedObject() : IntPtr.Zero;
                int resultLength;
                int status = encrypt
                    ? BCryptEncrypt(keyHandle, inputPointer, inputLength, ref info, IntPtr.Zero, 0, outputPointer, output.Length, out resultLength, 0)
                    : BCryptDecrypt(keyHandle, inputPointer, inputLength, ref info, IntPtr.Zero, 0, outputPointer, output.Length, out resultLength, 0);

                if (status == StatusAuthTagMismatch)
                {
                    // Nothing of a forged message is returned
                    Array.Clear(output, 0, output.Length);
                    throw new CryptographicException("The computed authentication value did not match the input");
                }
                CheckStatus(status);
            }
            finally
            {
                if (associatedDataHandle.IsAllocated)
                {
                    associatedDataHandle.Free();
                }
                tagHandle.Free();
                nonceHandle.Free();
                outputHandle.Free();
                inputHandle.Free();
                BCryptDestroyKey(keyHandle);
            }
        }

        private static IntPtr OpenAlgorithm(string chainingMode)
        {
            IntPtr algorithm;
            CheckStatus(BCryptOpenAlgorithmProvider(out algorithm, AesAlgorithm, null, 0));

            // The property value is a null terminated UTF-16 string; its length includes the terminator
            int status = BCryptSetProperty(algorithm, ChainingModeProperty, chainingMode, (chainingMode.Length + 1) * 2, 0);
            if (status != StatusSuccess)
            {
                BCryptCloseAlgorithmProvider(algorithm, 0);
                CheckStatus(status);
            }
            return algorithm;
        }

        private static void CheckStatus(int status)
        {
            if (status != StatusSuccess)
            {
                throw new CryptographicException("Windows CNG returned NTSTATUS 0x" + status.ToString("X8"));
            }
        }

        /// <summary>
        /// BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct AuthenticatedCipherModeInfo
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, string pbInput, int cbInput, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr hKey, IntPtr pbInput, int cbInput, ref AuthenticatedCipherModeInfo pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr hKey, IntPtr pbInput, int cbInput, ref AuthenticatedCipherModeInfo pPaddingInfo, IntPtr pbIV, int cbIV, IntPtr pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    }
}
#endif
