using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary
{
    public static class DateTimeExtensions
    {
        public static long ToUnixTimestamp(this DateTime date)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var time = date.ToUniversalTime().Subtract(epoch);
            return time.Ticks / TimeSpan.TicksPerSecond;
        }

    }
    public class JWTClaims
    {
        public JWTClaims()
        {

        }

        public JWTClaims(int minutes)
        {
            var dtNow = DateTime.Now;
            IssuedAt = dtNow.ToUnixTimestamp();
            ExpirationTime = dtNow.AddMinutes(minutes).ToUnixTimestamp();
            NotBefore = dtNow.ToUnixTimestamp();
        }

        [JsonProperty("iss")]
        public string Issuer { get; set; }
        [JsonProperty("aud")]
        public string Audience { get; set; }
        [JsonProperty("exp")]
        public long ExpirationTime { get; set; }
        [JsonProperty("nbf")]
        public long NotBefore { get; set; }
        [JsonProperty("iat")]
        public long IssuedAt { get; set; }
        [JsonProperty("scope")]
        public string Scope { get; set; }
        [JsonProperty("client_id")]
        public string ClientId { get; set; }
    }

    public class JWTHeader
    {
        [JsonProperty("alg")]
        public string Algorithm { get; set; } = "HS256";
        [JsonProperty("typ")]
        public string Type { get; set; } = "JWT";
    }
}
