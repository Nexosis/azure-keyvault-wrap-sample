using System;
using System.Configuration;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.KeyVault;
using System.Security.Cryptography;
using Microsoft.Azure.KeyVault.Core;
using System.Linq;

namespace AzureKeyVaultPoc
{
    public class Utils
    {
        private const int KEY_SIZE_BYTES = 32; // 256 bit key
        private const CipherMode CIPHER_MODE_CBC = CipherMode.CBC;

        // Retrive JWT token to be used for KeyVault access.
        internal async static Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);

            // TODO: additionally look into using cert / pfx validation instead of Application ID & key
            ClientCredential clientCred = new ClientCredential(
                ConfigurationManager.AppSettings["clientId"],
                ConfigurationManager.AppSettings["clientSecret"]);

            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token.");

            return result.AccessToken;
        }

        internal static string EncryptFile(string fileToEncrypt, string encryptedOutputFile, KeyVaultKeyResolver cloudResolver, string keyId)
        {
            // Generate Client Encryption Key (CEK)
            using (var random = new RNGCryptoServiceProvider())
            {
                var aeskey = new byte[KEY_SIZE_BYTES];

                try
                {
                    // Generate an 256 bit AES Key 
                    random.GetBytes(aeskey);

                    // Encrypt the file
                    Encrypt(fileToEncrypt, encryptedOutputFile, aeskey);

                    Console.WriteLine("Retrieving key: " + keyId);
                    using (var keyEncryptionKey = cloudResolver.ResolveKeyAsync(keyId, CancellationToken.None).GetAwaiter().GetResult())
                    {
                        Console.WriteLine("Retrived key: " + keyEncryptionKey.Kid);
                        // Take the AES Key we Generated and Encrypt it using KeyVault to wrap it.
                        Tuple<byte[], string> wrappedKey = keyEncryptionKey.WrapKeyAsync(aeskey, null /* algorithm */, CancellationToken.None).GetAwaiter().GetResult();

                        string keyVersion = new Uri(keyEncryptionKey.Kid).Segments.Last();
                        CipherData cb = new CipherData { AlgorithmName = wrappedKey.Item2, WrapedKey = Convert.ToBase64String(wrappedKey.Item1), CipherText = encryptedOutputFile, KeyVersion = keyVersion };

                        // TODO: Determine if the CipherData should contain a signature to prevent tampering.
                        // Need to enumerate the risks.

                        return Utils.Serialize(cb);
                    }
                }
                finally
                {
                    // Clear out the key material from memory
                    Array.Clear(aeskey, 0, aeskey.Length);
                }
            }
        }

        internal static void DecryptFile(string cipherTextPath, string encryptedMetadata, string decryptedOutput, KeyVaultKeyResolver cloudResolver, string keyId)
        {
            // Make sure encrypted file exists.
            if (!File.Exists(cipherTextPath)) {
                throw new FileNotFoundException("File not found.", cipherTextPath);
            }

            CipherData cb = Deserialize<CipherData>(encryptedMetadata);
            IKey keyEncryptionKey = null;
            try
            {
                keyEncryptionKey = cloudResolver.ResolveKeyAsync(keyId, CancellationToken.None).GetAwaiter().GetResult();
                var currentKeyVersion = new Uri(keyEncryptionKey.Kid).Segments.Last();

                if (!currentKeyVersion.Equals(cb.KeyVersion))
                {
                    Console.WriteLine("Data encrypted with different key version: {0} vs {1}", currentKeyVersion, cb.KeyVersion);
                    // version doesn't match - go get the correct key version to unwrap with.
                    string newKey = keyId + "/" + cb.KeyVersion;
                    Console.WriteLine("Retrieving different key: " + newKey);
                    keyEncryptionKey = cloudResolver.ResolveKeyAsync(newKey, CancellationToken.None).GetAwaiter().GetResult();
                }

                // Unwrap Key using KeyVault
                byte[] aesKey = keyEncryptionKey.UnwrapKeyAsync(Convert.FromBase64String(cb.WrapedKey), cb.AlgorithmName, CancellationToken.None).GetAwaiter().GetResult();

                DecryptFile(cipherTextPath, decryptedOutput, aesKey);
            }
            finally
            {
                if (keyEncryptionKey != null)
                {
                    keyEncryptionKey.Dispose();
                }
            }
        }

        // Encrypts an Object and retunrs a JSON object holding the encryption
        internal static string Encrypt(object o, KeyVaultKeyResolver cloudResolver, string keyId)
        {
            string jsonStringToEncrypt = Utils.Serialize(o);

            // Generate Client Encryption Key (CEK)
            using (var random = new RNGCryptoServiceProvider())
            {
                var aeskey = new byte[KEY_SIZE_BYTES];
                try
                {
                    // Generate an 256 bit AES Key 
                    random.GetBytes(aeskey);

                    // Encrypt the plaintext
                    string cipherText = Convert.ToBase64String(Encrypt(jsonStringToEncrypt, aeskey));

                    Console.WriteLine("Retrieving key: " + keyId);
                    using (var keyEncryptionKey = cloudResolver.ResolveKeyAsync(keyId, CancellationToken.None).GetAwaiter().GetResult())
                    {
                        Console.WriteLine("Retrived key: " + keyEncryptionKey.Kid);
                        // Take the AES Key we Generated and Encrypt it using KeyVault to wrap it.
                        Tuple<byte[], string> wrappedKey = keyEncryptionKey.WrapKeyAsync(aeskey, null /* algorithm */, CancellationToken.None).GetAwaiter().GetResult();

                        string keyVersion = new Uri(keyEncryptionKey.Kid).Segments.Last();
                        CipherData cb = new CipherData { AlgorithmName = wrappedKey.Item2, WrapedKey = Convert.ToBase64String(wrappedKey.Item1), CipherText = cipherText, KeyVersion = keyVersion };

                        // TODO: Determine if the CipherData should contain a signature to prevent tampering.
                        // Need to enumerate the risks.

                        return Utils.Serialize(cb);
                    }
                }
                finally
                {
                    // Clear out the key material from memory
                    Array.Clear(aeskey, 0, aeskey.Length);
                }
            }
        }

        internal static T Decrypt<T>(string encryptedData, KeyVaultKeyResolver cloudResolver, string keyId)
        {
            CipherData cb = Deserialize<CipherData>(encryptedData);
            IKey keyEncryptionKey = null;
            try
            {
                keyEncryptionKey = cloudResolver.ResolveKeyAsync(keyId, CancellationToken.None).GetAwaiter().GetResult();
                var currentKeyVersion = new Uri(keyEncryptionKey.Kid).Segments.Last();

                if (!currentKeyVersion.Equals(cb.KeyVersion))
                {
                    Console.WriteLine("Data encrypted with different key version: {0} vs {1}", currentKeyVersion, cb.KeyVersion);
                    // version doesn't match - go get the correct key version to unwrap with.
                    string newKey = keyId + "/" + cb.KeyVersion;
                    Console.WriteLine("Retrieving different key: " + newKey);
                    try
                    {
                        keyEncryptionKey = cloudResolver.ResolveKeyAsync(newKey, CancellationToken.None).GetAwaiter().GetResult();
                    }
                    catch (AggregateException ae)
                    {
                        Console.WriteLine("Cloudresolver could not retrieve key, version '" + cb.KeyVersion + "': " + ae.Message);
                        return default(T);
                    }
                }

                // Unwrap Key using KeyVault
                byte[] aesKey = keyEncryptionKey.UnwrapKeyAsync(Convert.FromBase64String(cb.WrapedKey), cb.AlgorithmName, CancellationToken.None).GetAwaiter().GetResult();

                string plainJson = Decrypt(Convert.FromBase64String(cb.CipherText), aesKey);

                using (var streamReader = new StringReader(plainJson))
                {
                    JsonReader jreader = new JsonTextReader(streamReader);
                    return new JsonSerializer().Deserialize<T>(jreader);
                }
            }
            finally
            {
                if (keyEncryptionKey != null)
                {
                    keyEncryptionKey.Dispose();
                }
            }
        }

        private static void Encrypt(string plainTextFilePath, string cipherTextFilePath, byte[] key)
        {
            byte[] iv = null;

            using (AesManaged aes = new AesManaged())
            {
                try
                {
                    aes.GenerateIV();
                    aes.Key = key;
                    iv = aes.IV;
                    aes.Mode = CIPHER_MODE_CBC;

                    using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                    {
                        using (FileStream fsInput = new FileStream(plainTextFilePath, FileMode.Open, FileAccess.Read))
                        {
                            using (FileStream fsEncrypted = new FileStream(cipherTextFilePath, FileMode.Create, FileAccess.Write))
                            {
                                using (CryptoStream cryptostream = new CryptoStream(fsEncrypted, encryptor, CryptoStreamMode.Write))
                                {
                                    // Prepend the IV to the begining of the file.
                                    // Using the raw FileStream
                                    fsEncrypted.Write(iv, 0, iv.Length);
                                    fsEncrypted.Flush();

                                    // read in source plaintext and encrypt it
                                    // by writing to the cryptostream
                                    int data;
                                    while ((data = fsInput.ReadByte()) != -1)
                                    {
                                        cryptostream.WriteByte((byte)data);
                                    }
                                    cryptostream.Flush();
                                }
                            }
                        }
                    }
                }
                finally
                {
                    aes.Clear();
                }
            }
        }

        private static byte[] Encrypt(string plainText, byte[] key)
        {
            byte[] encrypted = null;
            byte[] iv = null;

            try
            {
                using (AesManaged aes = new AesManaged())
                {
                    try
                    {
                        aes.GenerateIV();
                        aes.Key = key;
                        iv = aes.IV;
                        aes.Mode = CIPHER_MODE_CBC;

                        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                        using (var ms = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                using (var sw = new StreamWriter(cs))
                                {
                                    sw.Write(plainText);
                                }
                                encrypted = ms.ToArray();
                            }
                        }
                    }
                    finally
                    {
                        aes.Clear();
                    }
                }

                // Combine the cipherText and the Initialization Vector and return
                return CombineByteArrays(encrypted, iv);
            }
            finally
            {
                if (encrypted != null)
                {
                    Array.Clear(encrypted, 0, encrypted.Length);
                }
            }
        }

        private static string Decrypt(byte[] cipherTextAndIv, byte[] key)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                try
                {
                    aesAlg.Key = key;
                    // Clear out key material from memory
                    Array.Clear(key, 0, key.Length);

                    // calculate IV Size and Extract from ciphertext
                    byte[] IV = new byte[aesAlg.BlockSize / 8];
                    byte[] cipherText = new byte[cipherTextAndIv.Length - IV.Length];

                    Array.Copy(cipherTextAndIv, IV, IV.Length);
                    Array.Copy(cipherTextAndIv, IV.Length, cipherText, 0, cipherText.Length);

                    aesAlg.IV = IV;
                    aesAlg.Mode = CIPHER_MODE_CBC;

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (var ms = new MemoryStream(cipherText))
                    {
                        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                        {
                            using (var sr = new StreamReader(cs))
                            {
                                plaintext = sr.ReadToEnd();
                            }
                        }
                    }
                }
                finally
                {
                    aesAlg.Clear();
                }
            }

            return plaintext;
        }


        private static string DecryptFile(string cipherTextFile, string decryptedOutput, byte[] key)
        {
            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                try
                {
                    aesAlg.Key = key;
                    // Wipe out key material from memory
                    Array.Clear(key, 0, key.Length);

                    // calculate IV Size and Extract from ciphertext
                    byte[] iv = new byte[aesAlg.BlockSize / 8];

                    using (var fsCrypt = new FileStream(cipherTextFile, FileMode.Open))
                    {
                        // Read in IV from file stream.
                        fsCrypt.Read(iv, 0, iv.Length);
                        aesAlg.IV = iv;
                        aesAlg.Mode = CIPHER_MODE_CBC;

                        using (FileStream fsOut = new FileStream(decryptedOutput, FileMode.Create))
                        {
                            using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                            {
                                using (var cs = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Read))
                                {
                                    using (var sr = new StreamReader(cs))
                                    {
                                        int data;
                                        while ((data = cs.ReadByte()) != -1)
                                        {
                                            fsOut.WriteByte((byte)data);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                finally
                {
                    aesAlg.Clear();
                }
            }

            return plaintext;
        }

        private static byte[] CombineByteArrays(byte[] bytesArray1, byte[] byteArray2)
        {
            var combinedBytes = new byte[byteArray2.Length + bytesArray1.Length];
            Array.Copy(byteArray2, 0, combinedBytes, 0, byteArray2.Length);
            Array.Copy(bytesArray1, 0, combinedBytes, byteArray2.Length, bytesArray1.Length);
            return combinedBytes;
        }

        private static T Deserialize<T>(string jsonString)
        {
            using (var streamReader = new StringReader(jsonString))
            {
                JsonReader jreader = new JsonTextReader(streamReader);
                return new JsonSerializer().Deserialize<T>(jreader);
            }
        }

        private static string Serialize(object o)
        {
            using (var sw = new StringWriter())
            {
                new JsonSerializer().Serialize(sw, o);
                return sw.ToString();
            }
        }

        // TODO: When we move to .NET 4.5, we may be able to get rid of this method, or at least reduce our reliance upon it.
        // The ideal solution is to use async either everywhere or nowhere throughout a call to the Storage library, but this may
        // not be possible (KeyVault only exposes async APIs, and doesn't use ConfigureAwait(false), for example).
        // Blog post discussing this is here: http://blogs.msdn.com/b/pfxteam/archive/2012/04/13/10293638.aspx
        internal static void RunWithoutSynchronizationContext(Action actionToRun)
        {
            SynchronizationContext oldContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(null);
                actionToRun();
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(oldContext);
            }
        }

        internal static T RunWithoutSynchronizationContext<T>(Func<T> actionToRun)
        {
            SynchronizationContext oldContext = SynchronizationContext.Current;
            try
            {
                SynchronizationContext.SetSynchronizationContext(null);
                return actionToRun();
            }
            finally
            {
                SynchronizationContext.SetSynchronizationContext(oldContext);
            }
        }
    }
}