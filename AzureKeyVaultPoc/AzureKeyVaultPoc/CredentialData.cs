using Newtonsoft.Json;

namespace AzureKeyVaultPoc
{
    public class CredentialData
    {
        [JsonProperty("userName")]
        public string UserName { get; set; }
        [JsonProperty("password")]
        public string Password { get; set; }
    }
}
