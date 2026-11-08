namespace SMBLibrary.SMB2
{
    /// <summary>
    /// [MS-SMB2] 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
    /// </summary>
    public enum SigningAlgorithm : ushort
    {
        HmacSha256 = 0x0000,
        AesCmac = 0x0001,
        AesGmac = 0x0002,
    }
}
