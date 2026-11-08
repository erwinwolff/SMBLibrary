/* Copyright (C) 2026 Micro Formatica. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System.Diagnostics;
using System.Security.Cryptography;
using SMBLibrary;
using SMBLibrary.Client;
using SMBLibrary.SMB2;
using FileAttributes = SMBLibrary.FileAttributes;

namespace SMBClientConsole
{
    /// <summary>
    /// Command line SMB2/SMB3 client to test SMBLibrary against Windows and Samba servers: shows what was negotiated
    /// (dialect, cipher, signing algorithm) and runs file operations and a throughput test.
    /// </summary>
    internal static class Program
    {
        private const int ExitOk = 0;
        private const int ExitUsage = 1;
        private const int ExitConnect = 2;
        private const int ExitLogin = 3;
        private const int ExitOperation = 4;

        private static int Main(string[] args)
        {
            Options options;
            try
            {
                options = Options.Parse(args);
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
                Console.Error.WriteLine();
                PrintUsage();
                return ExitUsage;
            }

            if (options.ShowHelp || options.Server == null || options.Command == null)
            {
                PrintUsage();
                return options.ShowHelp ? ExitOk : ExitUsage;
            }

            SMB2Client client = new SMB2Client(options.TimeoutMilliseconds, options.EnableSMB311, true);
            if (options.Ciphers != null)
            {
                client.EncryptionCiphers = options.Ciphers;
            }
            if (options.SigningAlgorithms != null)
            {
                client.SigningAlgorithms = options.SigningAlgorithms;
            }

            Verbose(options, $"Connecting to {options.Server}:445 ...");
            if (!client.Connect(options.Server, SMBTransportType.DirectTCPTransport))
            {
                Console.Error.WriteLine($"Cannot connect to {options.Server} on port 445 (or no SMB2/3 dialect in common)");
                return ExitConnect;
            }

            try
            {
                string password = options.Password ?? Environment.GetEnvironmentVariable("SMB_PASSWORD") ?? ReadPassword($"Password for {options.User}: ");
                NTStatus loginStatus = client.Login(options.Domain, options.User, password);
                if (loginStatus != NTStatus.STATUS_SUCCESS)
                {
                    Console.Error.WriteLine($"Login failed: {loginStatus}");
                    PrintConnection(client);
                    return ExitLogin;
                }

                Verbose(options, "Logged in");
                if (options.Verbose || options.Command == "info")
                {
                    PrintConnection(client);
                }

                try
                {
                    return RunCommand(client, options) ? ExitOk : ExitOperation;
                }
                finally
                {
                    client.Logoff();
                }
            }
            catch (CryptographicException ex)
            {
                // A failed signature or decryption: the most likely interoperability problem
                Console.Error.WriteLine("Cryptographic failure: " + ex.Message);
                PrintConnection(client);
                return ExitOperation;
            }
            finally
            {
                client.Disconnect();
            }
        }

        private static bool RunCommand(SMB2Client client, Options options)
        {
            string[] a = options.Arguments;
            switch (options.Command)
            {
                case "info":
                    return true;
                case "shares":
                    return ListShares(client);
                case "ls":
                    Require(a, 1, "ls <share> [path]");
                    return WithShare(client, a[0], store => ListDirectory(store, a.Length > 1 ? a[1] : string.Empty));
                case "get":
                    Require(a, 2, "get <share> <remote path> [local file]");
                    return WithShare(client, a[0], store => Download(client, store, a[1], a.Length > 2 ? a[2] : Path.GetFileName(ToSmbPath(a[1]).Replace('\\', '/'))));
                case "put":
                    Require(a, 2, "put <share> <local file> [remote path]");
                    return WithShare(client, a[0], store => Upload(client, store, a[1], a.Length > 2 ? a[2] : Path.GetFileName(a[1])));
                case "mkdir":
                    Require(a, 2, "mkdir <share> <path>");
                    return WithShare(client, a[0], store => CreateDirectory(store, a[1]));
                case "rm":
                    Require(a, 2, "rm <share> <path>");
                    return WithShare(client, a[0], store => Delete(store, a[1]));
                case "bench":
                    Require(a, 1, "bench <share> [megabytes]");
                    int megabytes = a.Length > 1 ? int.Parse(a[1]) : 64;
                    return WithShare(client, a[0], store => Benchmark(client, store, megabytes));
                default:
                    throw new ArgumentException($"Unknown command '{options.Command}'");
            }
        }

        #region Commands

        private static bool ListShares(SMB2Client client)
        {
            List<string> shares = client.ListShares(out NTStatus status);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail("Listing shares", status);
            }

            foreach (string share in shares)
            {
                Console.WriteLine(share);
            }
            return true;
        }

        private static bool ListDirectory(ISMBFileStore store, string path)
        {
            NTStatus status = store.CreateFile(out object handle, out _, ToSmbPath(path), AccessMask.GENERIC_READ, FileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail($"Opening directory '{path}'", status);
            }

            try
            {
                status = store.QueryDirectory(out List<QueryDirectoryFileInformation> entries, handle, "*", FileInformationClass.FileDirectoryInformation);
                if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_NO_MORE_FILES)
                {
                    return Fail("Listing directory", status);
                }

                foreach (FileDirectoryInformation entry in entries.OfType<FileDirectoryInformation>().OrderBy(e => e.FileName, StringComparer.OrdinalIgnoreCase))
                {
                    if (entry.FileName == "." || entry.FileName == "..")
                    {
                        continue;
                    }

                    bool isDirectory = (entry.FileAttributes & FileAttributes.Directory) > 0;
                    string size = isDirectory ? "<DIR>" : entry.EndOfFile.ToString("N0");
                    Console.WriteLine($"{entry.LastWriteTime:yyyy-MM-dd HH:mm}  {size,15}  {entry.FileName}");
                }
                return true;
            }
            finally
            {
                store.CloseFile(handle);
            }
        }

        private static bool Download(SMB2Client client, ISMBFileStore store, string remotePath, string localPath)
        {
            NTStatus status = store.CreateFile(out object handle, out _, ToSmbPath(remotePath), AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE, FileAttributes.Normal,
                ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail($"Opening '{remotePath}'", status);
            }

            Stopwatch watch = Stopwatch.StartNew();
            long total = 0;
            try
            {
                using FileStream target = new FileStream(localPath, FileMode.Create, FileAccess.Write);
                while (true)
                {
                    status = store.ReadFile(out byte[] data, handle, total, (int)client.MaxReadSize);
                    if (status == NTStatus.STATUS_END_OF_FILE || (status == NTStatus.STATUS_SUCCESS && data.Length == 0))
                    {
                        break;
                    }
                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        return Fail("Reading", status);
                    }

                    target.Write(data, 0, data.Length);
                    total += data.Length;
                }
            }
            finally
            {
                store.CloseFile(handle);
            }

            Console.WriteLine($"Downloaded {total:N0} bytes to {localPath} in {watch.Elapsed.TotalSeconds:F2} s ({Throughput(total, watch.Elapsed)})");
            return true;
        }

        private static bool Upload(SMB2Client client, ISMBFileStore store, string localPath, string remotePath)
        {
            if (!File.Exists(localPath))
            {
                Console.Error.WriteLine($"Local file '{localPath}' does not exist");
                return false;
            }

            Stopwatch watch = Stopwatch.StartNew();
            long total;
            using (FileStream source = File.OpenRead(localPath))
            {
                if (!WriteStream(client, store, source, remotePath, out total))
                {
                    return false;
                }
            }

            Console.WriteLine($"Uploaded {total:N0} bytes to {remotePath} in {watch.Elapsed.TotalSeconds:F2} s ({Throughput(total, watch.Elapsed)})");
            return true;
        }

        private static bool CreateDirectory(ISMBFileStore store, string path)
        {
            NTStatus status = store.CreateFile(out object handle, out _, ToSmbPath(path), AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE, FileAttributes.Directory,
                ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_CREATE, CreateOptions.FILE_DIRECTORY_FILE, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail($"Creating directory '{path}'", status);
            }

            store.CloseFile(handle);
            Console.WriteLine($"Created directory {path}");
            return true;
        }

        /// <summary>
        /// Deletes a file or an empty directory
        /// </summary>
        private static bool Delete(ISMBFileStore store, string path)
        {
            NTStatus status = store.CreateFile(out object handle, out _, ToSmbPath(path), AccessMask.DELETE | AccessMask.SYNCHRONIZE, FileAttributes.Normal,
                ShareAccess.Read | ShareAccess.Write | ShareAccess.Delete, CreateDisposition.FILE_OPEN, CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail($"Opening '{path}'", status);
            }

            try
            {
                status = store.SetFileInformation(handle, new FileDispositionInformation { DeletePending = true });
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return Fail($"Deleting '{path}'", status);
                }
            }
            finally
            {
                store.CloseFile(handle);
            }

            Console.WriteLine($"Deleted {path}");
            return true;
        }

        /// <summary>
        /// Writes a file of random data, reads it back, compares and deletes it: throughput of the negotiated
        /// signing algorithm or cipher
        /// </summary>
        private static bool Benchmark(SMB2Client client, ISMBFileStore store, int megabytes)
        {
            string remotePath = $"smbclient-bench-{Guid.NewGuid():N}.tmp";
            byte[] content = RandomNumberGenerator.GetBytes(megabytes * 1024 * 1024);
            byte[] expectedHash = SHA256.HashData(content);

            Stopwatch watch = Stopwatch.StartNew();
            using (MemoryStream source = new MemoryStream(content, false))
            {
                if (!WriteStream(client, store, source, remotePath, out _))
                {
                    return false;
                }
            }
            TimeSpan writeTime = watch.Elapsed;

            NTStatus status = store.CreateFile(out object handle, out _, remotePath, AccessMask.GENERIC_READ | AccessMask.SYNCHRONIZE, FileAttributes.Normal,
                ShareAccess.Read, CreateDisposition.FILE_OPEN, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail("Opening the benchmark file", status);
            }

            watch.Restart();
            byte[] readBack = new byte[content.Length];
            long total = 0;
            try
            {
                while (total < readBack.Length)
                {
                    status = store.ReadFile(out byte[] data, handle, total, (int)client.MaxReadSize);
                    if (status != NTStatus.STATUS_SUCCESS || data.Length == 0)
                    {
                        return Fail("Reading the benchmark file", status);
                    }
                    Buffer.BlockCopy(data, 0, readBack, (int)total, data.Length);
                    total += data.Length;
                }
            }
            finally
            {
                store.CloseFile(handle);
            }
            TimeSpan readTime = watch.Elapsed;

            bool identical = SHA256.HashData(readBack).AsSpan().SequenceEqual(expectedHash);
            Delete(store, remotePath);

            Console.WriteLine($"Write: {Throughput(content.Length, writeTime)}");
            Console.WriteLine($"Read:  {Throughput(content.Length, readTime)}");
            Console.WriteLine(identical ? "Content verified" : "CONTENT DIFFERS");
            return identical;
        }

        #endregion

        #region Helpers

        private static bool WithShare(SMB2Client client, string share, Func<ISMBFileStore, bool> action)
        {
            ISMBFileStore store = client.TreeConnect(share, out NTStatus status);
            if (status != NTStatus.STATUS_SUCCESS || store == null)
            {
                return Fail($"Connecting to share '{share}'", status);
            }

            try
            {
                return action(store);
            }
            finally
            {
                store.Disconnect();
            }
        }

        private static bool WriteStream(SMB2Client client, ISMBFileStore store, Stream source, string remotePath, out long total)
        {
            total = 0;
            NTStatus status = store.CreateFile(out object handle, out _, ToSmbPath(remotePath), AccessMask.GENERIC_WRITE | AccessMask.SYNCHRONIZE, FileAttributes.Normal,
                ShareAccess.None, CreateDisposition.FILE_OVERWRITE_IF, CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_SYNCHRONOUS_IO_ALERT, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return Fail($"Creating '{remotePath}'", status);
            }

            try
            {
                byte[] buffer = new byte[client.MaxWriteSize];
                int read;
                while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
                {
                    byte[] chunk = read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
                    status = store.WriteFile(out int written, handle, total, chunk);
                    if (status != NTStatus.STATUS_SUCCESS || written != read)
                    {
                        return Fail("Writing", status);
                    }
                    total += written;
                }
                return true;
            }
            finally
            {
                store.CloseFile(handle);
            }
        }

        // SMB2 paths are relative to the share and use backslashes
        private static string ToSmbPath(string path)
        {
            return path.Replace('/', '\\').Trim('\\');
        }

        private static void PrintConnection(SMB2Client client)
        {
            Console.WriteLine($"Dialect:            {DialectName(client.Dialect)}");
            Console.WriteLine($"Signing:            {client.SigningAlgorithm}{(client.IsSigningRequired ? " (required)" : string.Empty)}");
            Console.WriteLine($"Encryption:         {(client.IsEncryptionSupported ? client.Cipher.ToString() : "not available")}");
            Console.WriteLine($"Session encrypted:  {(client.IsSessionEncrypted ? "yes (required by the server)" : "no (shares may still require it)")}");
            Console.WriteLine($"Max read / write:   {client.MaxReadSize:N0} / {client.MaxWriteSize:N0} bytes");
        }

        private static string DialectName(SMB2Dialect dialect)
        {
            switch (dialect)
            {
                case SMB2Dialect.SMB202: return "SMB 2.0.2";
                case SMB2Dialect.SMB210: return "SMB 2.1";
                case SMB2Dialect.SMB300: return "SMB 3.0";
                case SMB2Dialect.SMB302: return "SMB 3.0.2";
                case SMB2Dialect.SMB311: return "SMB 3.1.1";
                default: return dialect.ToString();
            }
        }

        private static string Throughput(long bytes, TimeSpan elapsed)
        {
            double seconds = Math.Max(elapsed.TotalSeconds, 0.001);
            return $"{bytes / 1024d / 1024d / seconds:F1} MB/s";
        }

        private static bool Fail(string action, NTStatus status)
        {
            Console.Error.WriteLine($"{action} failed: {status}");
            return false;
        }

        private static void Require(string[] arguments, int count, string usage)
        {
            if (arguments.Length < count)
            {
                throw new ArgumentException("Usage: " + usage);
            }
        }

        private static void Verbose(Options options, string message)
        {
            if (options.Verbose)
            {
                Console.WriteLine(message);
            }
        }

        private static string ReadPassword(string prompt)
        {
            if (Console.IsInputRedirected)
            {
                return Console.ReadLine() ?? string.Empty;
            }

            Console.Write(prompt);
            var password = new System.Text.StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    break;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Length--;
                    }
                    continue;
                }
                if (!char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                }
            }
            Console.WriteLine();
            return password.ToString();
        }

        private static void PrintUsage()
        {
            Console.WriteLine("""
                smbclient - SMB2/SMB3 test client (SMBLibrary)

                Usage:
                  smbclient <server> [options] <command> [arguments]

                Commands:
                  info                                  Connect, log in and show what was negotiated
                  shares                                List the shares
                  ls <share> [path]                     List a directory
                  get <share> <remote path> [local]     Download a file
                  put <share> <local file> [remote]     Upload a file (overwrites)
                  mkdir <share> <path>                  Create a directory
                  rm <share> <path>                     Delete a file or an empty directory
                  bench <share> [megabytes]             Write, read back, verify and delete a test file (default 64 MB)

                Options:
                  -u, --user <user>                     DOMAIN\user, user@domain or user
                  -p, --password <password>             Otherwise SMB_PASSWORD, otherwise asked for
                  -d, --domain <domain>                 Domain (also taken from DOMAIN\user)
                  --ciphers <list>                      Ciphers to offer, in order: aes128gcm,aes128ccm,aes256gcm,aes256ccm
                  --signing <list>                      Signing algorithms to offer, in order: gmac,cmac,hmac
                  --no-smb311                           Offer SMB 2.0.2 up to 3.0.2 only
                  --timeout <milliseconds>              Response timeout (default 5000)
                  -v, --verbose                         Show progress and the negotiated parameters
                  -h, --help                            This text

                Examples:
                  smbclient fileserver -u CORP\alice info
                  smbclient fileserver -u alice --ciphers aes256gcm bench Data 256
                  smbclient 192.168.1.10 -u alice --signing gmac get Data reports/q3.pdf

                Exit codes: 0 ok, 1 usage, 2 connection, 3 login, 4 operation failed
                """);
        }

        #endregion
    }

    internal sealed class Options
    {
        public string? Server;
        public string? Command;
        public string[] Arguments = Array.Empty<string>();
        public string User = string.Empty;
        public string? Password;
        public string Domain = string.Empty;
        public List<CipherAlgorithm>? Ciphers;
        public List<SigningAlgorithm>? SigningAlgorithms;
        public bool EnableSMB311 = true;
        public int TimeoutMilliseconds = SMB2Client.DefaultResponseTimeoutInMilliseconds;
        public bool Verbose;
        public bool ShowHelp;

        public static Options Parse(string[] args)
        {
            Options options = new Options();
            List<string> positional = new List<string>();

            for (int index = 0; index < args.Length; index++)
            {
                string arg = args[index];
                switch (arg)
                {
                    case "-u":
                    case "--user":
                        options.User = Value(args, ref index, arg);
                        break;
                    case "-p":
                    case "--password":
                        options.Password = Value(args, ref index, arg);
                        break;
                    case "-d":
                    case "--domain":
                        options.Domain = Value(args, ref index, arg);
                        break;
                    case "--ciphers":
                        options.Ciphers = ParseList(Value(args, ref index, arg), ParseCipher);
                        break;
                    case "--signing":
                        options.SigningAlgorithms = ParseList(Value(args, ref index, arg), ParseSigning);
                        break;
                    case "--no-smb311":
                        options.EnableSMB311 = false;
                        break;
                    case "--timeout":
                        options.TimeoutMilliseconds = int.Parse(Value(args, ref index, arg));
                        break;
                    case "-v":
                    case "--verbose":
                        options.Verbose = true;
                        break;
                    case "-h":
                    case "--help":
                    case "/?":
                        options.ShowHelp = true;
                        break;
                    default:
                        if (arg.StartsWith("-", StringComparison.Ordinal) && arg.Length > 1)
                        {
                            throw new ArgumentException($"Unknown option '{arg}'");
                        }
                        positional.Add(arg);
                        break;
                }
            }

            if (positional.Count > 0)
            {
                options.Server = positional[0];
            }
            if (positional.Count > 1)
            {
                options.Command = positional[1].ToLowerInvariant();
                options.Arguments = positional.Skip(2).ToArray();
            }

            // DOMAIN\user; user@domain is passed on as it is (NTLM accepts the UPN form)
            int backslash = options.User.IndexOf('\\');
            if (backslash > 0)
            {
                options.Domain = options.User.Substring(0, backslash);
                options.User = options.User.Substring(backslash + 1);
            }

            return options;
        }

        private static string Value(string[] args, ref int index, string option)
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException($"Option {option} needs a value");
            }
            index++;
            return args[index];
        }

        private static List<T> ParseList<T>(string value, Func<string, T> parse)
        {
            return value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(parse).ToList();
        }

        private static CipherAlgorithm ParseCipher(string value)
        {
            switch (value.ToLowerInvariant().Replace("-", string.Empty).Replace("_", string.Empty))
            {
                case "aes128ccm": return CipherAlgorithm.Aes128Ccm;
                case "aes128gcm": return CipherAlgorithm.Aes128Gcm;
                case "aes256ccm": return CipherAlgorithm.Aes256Ccm;
                case "aes256gcm": return CipherAlgorithm.Aes256Gcm;
                default: throw new ArgumentException($"Unknown cipher '{value}'");
            }
        }

        private static SigningAlgorithm ParseSigning(string value)
        {
            switch (value.ToLowerInvariant().Replace("-", string.Empty))
            {
                case "gmac":
                case "aesgmac": return SigningAlgorithm.AesGmac;
                case "cmac":
                case "aescmac": return SigningAlgorithm.AesCmac;
                case "hmac":
                case "hmacsha256": return SigningAlgorithm.HmacSha256;
                default: throw new ArgumentException($"Unknown signing algorithm '{value}'");
            }
        }
    }
}
