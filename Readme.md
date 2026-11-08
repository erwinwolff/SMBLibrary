About SMBLibrary:
=================
SMBLibrary is an open-source C# SMB 1.0/CIFS, SMB 2.0, SMB 2.1 and SMB 3.0 server and client implementation.  
SMBLibrary gives .NET developers an easy way to share a directory / file system / virtual file system or to connect to an existing share, with any operating system that supports the SMB protocol.  
SMBLibrary is modular, you can take advantage of Integrated Windows Authentication and the Windows storage subsystem on a Windows host or use independent implementations that allow for cross-platform compatibility.  
SMBLibrary can communicate with any Windows version since Windows NT 4.0.  

About this fork:
================
This fork is maintained by Micro Formatica. It remains licensed under the LGPL (version 3 or later), like the original.
The changes compared to SMBLibrary 1.5.8.1:

###### Target frameworks
- The libraries target .NET Framework 4.8.1 and .NET 10 (net481;net10.0). Support for .NET 2.0, .NET 4.0, .NET Standard 2.0 and .NET Core 3.1 was removed.
- SMBServer targets net481;net10.0-windows, the tests target net481;net10.0 and use MSTest 4.
- Framework specific code uses the NET and NETFRAMEWORK symbols. The .NET 2.0 code paths (Thread.Abort, the C# 2.0 Parallel helper) are gone.
- Obsolete APIs were replaced: RijndaelManaged by Aes, System.TimeZone by TimeZoneInfo, the TCP keep-alive constants by the named socket options of .NET.

###### Security fix: secure random numbers
- System.Random was used for the NTLM session key, the NTLM client and server challenges, the AES-CCM nonces and the SMB 3.1.1 pre-authentication salt. On .NET Framework every new Random() is seeded with the tick count, so these values were predictable and AES-CCM nonces could repeat under the same key.
- All of them now come from a cryptographically secure generator (Utilities.SecureRandom).

###### SMB 3.1.1 encryption
- In addition to AES-128-CCM the client negotiates AES-128-GCM, AES-256-GCM and AES-256-CCM (SMB2_ENCRYPTION_CAPABILITIES). AES-256 ciphers use 256 bit keys.
- AES-GCM uses the AesGcm class of .NET 10. .NET Framework has no AES-GCM, so a managed implementation is used there (Utilities.AesGcmCipher), verified against the NIST test vectors and the .NET implementation.
- Cipher preference: GCM first on .NET 10, CCM first on .NET Framework (where the managed GCM is slower than CCM).
- If a session or share requires encryption but no cipher was negotiated, the client returns STATUS_ACCESS_DENIED instead of sending data in plain text.
- Fixed: the cipher list of SMB2_ENCRYPTION_CAPABILITIES was read two bytes too early.

###### SMB 3.1.1 signing
- The client negotiates AES-GMAC signing (SMB2_SIGNING_CAPABILITIES, RFC 4543), with AES-CMAC as fallback. The order follows the cipher preference above.
- Without a signing context the dialect decides as before: HMAC-SHA256 for SMB 2.x, AES-CMAC for SMB 3.x.

###### Notes
- SMB 3.1.1 is still enabled per client: new SMB2Client(true).
- The server side is unchanged and supports dialects up to SMB 3.0.
- The changes are covered by unit tests; interoperability tests against Windows and Samba servers are still to be done.

Supported SMB / CIFS transport methods:
=======================================
• NetBIOS over TCP (port 139)  
• Direct TCP hosting (port 445)

###### 'NetBIOS over TCP' and 'Direct TCP hosting' are almost identical, the only differences:
- A 'session request' packet is initiating the NBT connection.
- A 'keep alive' packet is sent from time to time over NBT connections.
- SMB2: Direct TCP hosting supports large MTUs.

Using SMBLibrary:
=================
Server notes can be found [here](ServerNotes.md).

Client code examples can be found [here](ClientExamples.md).

NuGet Packages:
===============
[SMBLibrary](https://www.nuget.org/packages/SMBLibrary/) - Cross-platform server and client implementation.  
[SMBLibrary.Win32](https://www.nuget.org/packages/SMBLibrary.Win32/) - Allows utilizing Integrated Windows Authentication and/or the Windows storage subsystem on a Windows host.  
[SMBLibrary.Adapters](https://www.nuget.org/packages/SMBLibrary.Adapters/) - IFileSystem to INTFileStore adapter for SMBLibrary.  

Licensing:
==========
A commercial license of SMBLibrary is available for a fee.  
This is intended for companies who are unable to use the LGPL version.  
Please contact me for additional details.  

Contributions:
==============
If you choose to make a contribution to this project, you must agree to irrevocably assign to SMBLibrary and/or Tal Aloni all worldwide copyright and intellectual property rights in and to your contribution, effective upon submission.  

Contact:
========
If you have any question, feel free to contact me.  
Tal Aloni <tal.aloni.il@gmail.com>
