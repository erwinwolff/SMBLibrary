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
    /// Cryptographically secure random bytes for keys, challenges, nonces and salts.
    /// System.Random must never be used for these: on .NET Framework every new Random() is seeded with the tick
    /// count, so instances created within the same clock tick return the same sequence, and the values are
    /// predictable for anyone who can guess the time.
    /// </summary>
    public static class SecureRandom
    {
        public static void GetBytes(byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

#if NET
            RandomNumberGenerator.Fill(buffer);
#else
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
#endif
        }

        public static byte[] GetBytes(int length)
        {
            byte[] buffer = new byte[length];
            GetBytes(buffer);
            return buffer;
        }
    }
}
