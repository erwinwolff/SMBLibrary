/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// [MS-SMB2] 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
    /// </summary>
    public class SigningCapabilities : NegotiateContext
    {
        // ushort SigningAlgorithmCount;
        public List<SigningAlgorithm> SigningAlgorithms = new List<SigningAlgorithm>();

        public SigningCapabilities()
        {
        }

        public SigningCapabilities(byte[] buffer, int offset) : base(buffer, offset)
        {
            ushort signingAlgorithmCount = LittleEndianConverter.ToUInt16(Data, 0);
            for (int index = 0; index < signingAlgorithmCount; index++)
            {
                SigningAlgorithms.Add((SigningAlgorithm)LittleEndianConverter.ToUInt16(Data, 2 + index * 2));
            }
        }

        public override void WriteData()
        {
            Data = new byte[DataLength];
            LittleEndianWriter.WriteUInt16(Data, 0, (ushort)SigningAlgorithms.Count);
            for (int index = 0; index < SigningAlgorithms.Count; index++)
            {
                LittleEndianWriter.WriteUInt16(Data, 2 + index * 2, (ushort)SigningAlgorithms[index]);
            }
        }

        public override int DataLength
        {
            get
            {
                return 2 + SigningAlgorithms.Count * 2;
            }
        }

        public override NegotiateContextType ContextType => NegotiateContextType.SMB2_SIGNING_CAPABILITIES;
    }
}
