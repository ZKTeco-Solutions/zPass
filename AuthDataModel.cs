using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace zPassLibrary
{
    public class TokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("token_type")]
        public string TokenType { get; set; } = "Bearer";
        [JsonProperty("expires_in")]
        public long ExpiresIn { get; set; }
    }

    public class AuthorizeParameter
    {
        [JsonProperty("software_id")]
        public string SoftwareId { get; set; }
        [JsonProperty("scope")]
        public string Scope { get; set; }
        [JsonProperty("web_token_id")]
        public string WebTokenId { get; set; }
    }

    public class RequestAuthorizationParameter
    {
        public string ClientId { get; set; }
        public string Scope { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
        public string SoftwareName { get; set; }
        public string OrganizationName { get; set; }

    }

    public class RequestAuthorizationResponse
    {
        [JsonProperty("status")]
        public string Status { get; set; }
        [JsonProperty("request_id")]
        public string RequestId { get; set; }
        [JsonProperty("expires_in")]
        public long ExpiresIn { get; set; }
    }

}
