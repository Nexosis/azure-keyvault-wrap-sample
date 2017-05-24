using System;
using Newtonsoft.Json;

namespace AzureKeyVaultPoc
{
    public class CipherData
    {
        [JsonProperty("an")]
        public string AlgorithmName { get; set; }

        [JsonProperty("wk")]
        public string WrapedKey { get; set; }

        [JsonProperty("ct")]
        public string CipherText { get; set; }

        [JsonProperty("kv")]
        public string KeyVersion { get; set; }
    }
}
