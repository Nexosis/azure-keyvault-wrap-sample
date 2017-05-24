# Azure KeyVault using HSM and Envelope Technique

Sample that illustrates how to leverage Azure KeyVault for centralized Key Management to wrap / unwrap one-time symmetric keys for encrypting serialized data at rest.

## Encryption Steps:
 * Generates an AES symmetric key. This is to be a limited-use symmetric key. If there are changes to the underlying data just re-gen a new IV/symmetric key - the bits are free.
 * Data at rest is encrypted using this.
 * This AES Symmetric key is then wrapped (encrypted) using key encryption key stored in KeyVault. This key is identified by a Key Identifier and is an asymmetric key pair managed and stored in Azure Key Vault allowing for auditing, key versioning, etc.
 * The client systems never have access to the KeyVault key, but instead invoke the key wrapping algorithm provided by Azure Key Vault using the API.
 * The encrypted data can then be stored anywhere. The wrapped key along with some additional encryption metadata must be stored along with the encrypted data.

## Decryption Steps:
 * Library assumes the key encryption key is managed in Azure Key Vaults. The user does not need to know the specific key that was used for encryption. Instead, the key resolver which resolves different key identifiers to keys can be set up and used.
 * The library downloads the encrypted data along with any encryption material that is stored in the KeyVault service.
 * The wrapped (encrypted) symmetric key is then unwrapped (decrypted) using the Azure KeyVault key. The client library does not have access to the key itself. It simply invokes the Key Vault provider's unwrapping algorithm.
 * The symmetric key is then used to decrypt the encrypted user data.

### The Following Nuget packages must be installed:
```
PM> Install-Package Microsoft.Azure.KeyVault
PM> Install-Package Microsoft.Azure.KeyVault.Extensions
PM> Install-Package Microsoft.IdentityModel.Clients.ActiveDirectory -Version 2.16.204221202
```
### Sample Output

What's stored in the Encrypted JSON object below:
 * an = string Algorithm Name, 'RSA-OAEP' for now.
 * wk = base64(encrypted/wrapped AES Key)
 * ct = base64(iv+cipherText) - (NOTE: for file encryption, the path to the encrypted file is put here and the IV is pre-pended to the encrypted file).
 * kv = Key Version

```
Object to encrypt...
UserName: bob Password: password123

Encrypting object...
{
	"an":"RSA-OAEP",
	"wk":"FQ0Kzb1q676wRDdJIREjGmRWWBp4MgYsYGxoXQ0KHCQLYhFrC35gIyordCw4aSA3C0MQDQo/bwVAX++1jCxvGEICMkJgNR5fZiQYGRUZEhHlrK9+1porJlJ3ezJeDmFSBu6emRQMNC5dEEFndggmBFERRRdNAhYME0BXPGUSKmE0fzItNRcpL28tN1RvHi1aZNesAk/ckAYBGF1BJ09TJit8FQ==",
	"ct":"US9iJzUpw7giAnZDTDsZRQJxSUbLsljCgT9dPlZsHw==",
	"kv":"abcdefghijklmnopqrstuvwxyz0123456"
}

Decrypting object...
UserName: bob Password: password123
```

### References for more information

 * [Azure Key Vault Developer's Guide](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-developers-guide)
 * [azure-sdk-for-net/src/SDKs/KeyVault/](https://github.com/Azure/azure-sdk-for-net/tree/2467032622b88338abd2bae2433a60abf6ba5656/src/SDKs/KeyVault)
 * [azure-storage-net/Samples/GettingStarted/EncryptionSamples/](https://github.com/Azure/azure-storage-net/tree/master/Samples/GettingStarted/EncryptionSamples)
 * [Protecting Sensitive Data with Azure Key Vault](https://blogs.msdn.microsoft.com/data_insights_global_practice/2015/09/24/protecting-sensitive-data-with-azure-key-vault/)
 * [Microsoft.Azure.KeyVault Namespace](https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.keyvault?redirectedfrom=MSDN&view=azurekeyvault-2.0.6#microsoft_azure_keyvault)
 * [About keys, secrets, and certificates](https://docs.microsoft.com/en-us/rest/api/keyvault/about-keys--secrets-and-certificates)
 * [Securing Secrets Using Azure Key Vault and Config Encryption](https://kamranicus.com/posts/2016-02-20-azure-key-vault-config-encryption-azure)
 * [Accessing Key Vault from a native application](https://blogs.technet.microsoft.com/kv/2016/09/17/accessing-key-vault-from-a-native-application/)
 * [Use Azure Key Vault from a Web Application](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-use-from-web-application)
 * [Azure Key Vault – Step by Step](https://blogs.technet.microsoft.com/kv/2015/06/02/azure-key-vault-step-by-step/)
 * [Client-Side Encryption and Azure Key Vault for Microsoft Azure Storage](https://docs.microsoft.com/en-us/azure/storage/storage-client-side-encryption)
 * [Tutorial: Encrypt and decrypt blobs in Microsoft Azure Storage using Azure Key Vault](https://docs.microsoft.com/en-us/azure/storage/storage-encrypt-decrypt-blobs-key-vaultit)
 * [Set up Azure Key Vault with end-to-end key rotation and auditing](https://docs.microsoft.com/en-us/azure/key-vault/key-vault-key-rotation-log-monitoring)
 * [azure-storage-net/Lib/ClassLibraryCommon/Blob/BlobEncryptionPolicy.cs](https://github.com/Azure/azure-storage-net/blob/master/Lib/ClassLibraryCommon/Blob/BlobEncryptionPolicy.cs)
 * [azure-storage-net/Lib/ClassLibraryCommon/Table/TableEncryptionPolicy.cs](https://github.com/Azure/azure-storage-net/blob/afc5c6d99a805fb4165631ab5cfd139238b00e71/Lib/ClassLibraryCommon/Table/TableEncryptionPolicy.cs) 
