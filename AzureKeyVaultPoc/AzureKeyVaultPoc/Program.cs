using Microsoft.Azure.KeyVault;
using System;
using System.Configuration;
using System.IO;

namespace AzureKeyVaultPoc
{
    class Program
    {
        // Required Nuget Pacakges:
        //
        // PM> Install-Package Microsoft.Azure.KeyVault
        // PM> Install-Package Microsoft.Azure.KeyVault.Extensions
        // PM> This is the latest stable release for ADAL 
        //
        // (AuthenticationContext, ClientCredential, AuthenticationResult)
        //
        // PM> Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory -Version 2.16.204221202
        static void Main(string[] args)
        {
            // Get a ref to the cloudResolver used to unwrap AES key using RSA
            KeyVaultKeyResolver cloudResolver = new KeyVaultKeyResolver(Utils.GetToken);
            string keyId = ConfigurationManager.AppSettings["KeyUri"];

            // Create an object to Serialize to JSON and then Encrypt
            CredentialData cb = new CredentialData { UserName = "bob", Password = "password123" };

            Console.WriteLine("Object to encrypt...");
            Console.WriteLine("UserName: " + cb.UserName + " Password: " + cb.Password);
            Console.WriteLine();

            // Encrypt a file
            string baseFileName = @"C:\code\temp\Nexosis-Wallpaper";
            string fileToEncrypt = baseFileName + ".jpg";
            string encryptedOutputFile= baseFileName + ".aes";

            Console.WriteLine("Encrypting file: " + fileToEncrypt);
            string encryptedmetaData = Utils.EncryptFile(fileToEncrypt, encryptedOutputFile, cloudResolver, keyId);
            Console.WriteLine("Encrypted file: " + encryptedOutputFile);
            Console.WriteLine(encryptedmetaData);
            Console.WriteLine();

            string decryptedOutput = encryptedOutputFile + "2.jpg";
            Console.WriteLine("Decrypting file: " + encryptedOutputFile);
            Utils.DecryptFile(encryptedOutputFile, encryptedmetaData, decryptedOutput, cloudResolver, keyId);
            Console.WriteLine("Decrypted file: " + decryptedOutput);
            Console.WriteLine();

            Console.WriteLine("Encrypting object...");
            // Serialize and Encrypt
            string encryptedCredential = Utils.Encrypt(cb, cloudResolver, keyId);
            Console.WriteLine("Encrypted:");
            Console.WriteLine(encryptedCredential);
            Console.WriteLine();
             
            Console.WriteLine("Decrypting object...");
            // Take an encrypted object Decrypt an deserialize back to obj type
            CredentialData cb2 = Utils.Decrypt<CredentialData>(encryptedCredential, cloudResolver, keyId);
            Console.WriteLine("UserName: " + cb2.UserName + " Password: " + cb2.Password);

            Console.WriteLine();
            Console.WriteLine("Decrypting stored data that has an older key version.");
            string decryptThis = File.ReadAllText("creds.json");
            // Take an encrypted object Decrypt an deserialize back to obj type with different version
            CredentialData cb3 = Utils.Decrypt<CredentialData>(decryptThis, cloudResolver, keyId);
            if (cb3 != null)
            {
                Console.WriteLine("UserName: " + cb3.UserName + " Password: " + cb3.Password);
            }

            Console.ReadLine();
        }
    }
}
