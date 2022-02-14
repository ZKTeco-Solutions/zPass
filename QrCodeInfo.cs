using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;

namespace zPassLibrary
{
    public class QrCodeInfo
    {
        [JsonProperty("iss")]
        public byte[] Issuer { get; set; }

        [JsonProperty("name")]
        public string IssuerName { get; set; }

        [JsonProperty("req")]
        public string[] Request { get; set; }

        [JsonProperty("iat")]
        public DateTime DateIssued { get; set; }

        [JsonProperty("url")]
        public string Url { get; set; }

        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("typ")] 
        public string Type { get; set; }

     }
}
