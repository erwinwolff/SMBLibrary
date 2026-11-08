/* Based on https://stackoverflow.com/a/30123190/3419770
 */
using System;
using System.Security.Cryptography;

namespace Utilities
{
    /// <summary>
    /// AES-CMAC (RFC 4493). The message is fed to the platform AES in CBC mode (hardware accelerated) in chunks, straight
    /// from the caller's buffer: no copy of the message is made.
    /// </summary>
    public static class AesCmac
    {
        private const int BlockSize = 16;

        // Multiple of the block size; bounds the scratch buffer for the CBC output that is thrown away
        private const int ChunkSize = 64 * 1024;

        public static byte[] CalculateAesCmac(byte[] key, byte[] data)
        {
            return CalculateAesCmac(key, data, 0, data.Length);
        }

        public static byte[] CalculateAesCmac(byte[] key, byte[] buffer, int offset, int length)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Padding = PaddingMode.None;
                aes.Key = key;

                // Subkey generation: L = AES(K, 0^128), K1 = L << 1 (xor Rb), K2 = K1 << 1 (xor Rb)
                byte[] l;
                aes.Mode = CipherMode.ECB;
                using (ICryptoTransform ecb = aes.CreateEncryptor())
                {
                    l = ecb.TransformFinalBlock(new byte[BlockSize], 0, BlockSize);
                }

                byte[] firstSubkey = Rol(l);
                if ((l[0] & 0x80) == 0x80)
                {
                    firstSubkey[15] ^= 0x87;
                }

                byte[] secondSubkey = Rol(firstSubkey);
                if ((firstSubkey[0] & 0x80) == 0x80)
                {
                    secondSubkey[15] ^= 0x87;
                }

                // A complete last block is xor'ed with K1; otherwise it is padded with 10^i and xor'ed with K2
                bool lastBlockComplete = length != 0 && length % BlockSize == 0;
                int lastBlockStart = lastBlockComplete ? length - BlockSize : length - length % BlockSize;
                int lastBlockLength = length - lastBlockStart;

                byte[] lastBlock = new byte[BlockSize];
                Array.Copy(buffer, offset + lastBlockStart, lastBlock, 0, lastBlockLength);
                byte[] subkey = lastBlockComplete ? firstSubkey : secondSubkey;
                if (!lastBlockComplete)
                {
                    lastBlock[lastBlockLength] = 0x80;
                }
                for (int index = 0; index < BlockSize; index++)
                {
                    lastBlock[index] ^= subkey[index];
                }

                // CBC with a zero IV over all blocks; the MAC is the last cipher block
                aes.Mode = CipherMode.CBC;
                aes.IV = new byte[BlockSize];
                using (ICryptoTransform cbc = aes.CreateEncryptor())
                {
                    byte[] scratch = new byte[Math.Min(ChunkSize, Math.Max(lastBlockStart, BlockSize))];
                    for (int done = 0; done < lastBlockStart; )
                    {
                        int chunk = Math.Min(scratch.Length, lastBlockStart - done);
                        cbc.TransformBlock(buffer, offset + done, chunk, scratch, 0);
                        done += chunk;
                    }

                    return cbc.TransformFinalBlock(lastBlock, 0, BlockSize);
                }
            }
        }

        private static byte[] Rol(byte[] b)
        {
            byte[] r = new byte[b.Length];
            byte carry = 0;

            for (int i = b.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }

            return r;
        }
    }
}
