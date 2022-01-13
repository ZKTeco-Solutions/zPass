using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;

namespace zPassLibrary
{
    public class zPassConnect
    {
		public static string Connection { get; set; } = "https://localhost:5001";
		public static async Task<bool> HttpPost<T>(string url, object value, List<KeyValuePair<string,string>> headers, Func<T, Task<bool>> OnSuccess, Func<string, Task> OnError)
		{
			var client = new HttpClient();
			var retVal = false;

			var contractResolver = new DefaultContractResolver
			{
				NamingStrategy = new  CamelCaseNamingStrategy()
			};

			var serializationSettings = new JsonSerializerSettings()
			{
				ContractResolver = contractResolver,
				Formatting = Formatting.Indented
			};

			var json = JsonConvert.SerializeObject(value, serializationSettings );

			var content = new StringContent(json, Encoding.UTF8, "application/json");
			if( headers != null )
            {
				foreach( var h in headers)
                {
					client.DefaultRequestHeaders.Add(h.Key, h.Value);
                }
            }

			var result = await client.PostAsync(url, content);
			if (result.IsSuccessStatusCode)
			{
				var strResp = await result.Content.ReadAsStringAsync();
				var resp = JsonConvert.DeserializeObject<T>(strResp, serializationSettings);

				retVal = await OnSuccess(resp);
			}
			else
			{
				await OnError(result.StatusCode.ToString());
			}

			return retVal;
		}
		public static async Task<bool> HttpGet<T>(string url, Func<T, Task<bool>> OnSuccess, Func<Task> OnError)
		{
			var retVal = false;
			var client = new HttpClient();
			var result = await client.GetAsync(url);
			if (result.IsSuccessStatusCode)
			{
				var strResp = await result.Content.ReadAsStringAsync();

				var contractResolver = new DefaultContractResolver
				{
					NamingStrategy = new SnakeCaseNamingStrategy()
				};

				var serializationSettings = new JsonSerializerSettings()
				{
					ContractResolver = contractResolver,
					Formatting = Formatting.Indented
				};


				var resp = JsonConvert.DeserializeObject<T>(strResp, serializationSettings);

				retVal = await OnSuccess(resp);
			}
			else
			{
				await OnError();
			}

			return retVal;
		}

		public static async Task<string> CreateRequest(Entity company, Entity software, string redirectUri, string[] roles)
        {
			var req = new RequestAuthorizationParameter
			{
				ClientId = Convert.ToBase64String(software.PublicKey),
				OrganizationName = company.Identity,
				RedirectUri = redirectUri,
				Roles = roles,
				SoftwareName = software.Identity,
				State = ""
			};

			var handler = new JsonWebTokenHandler();
			var signKey = zPassSecurityKey.CreateSignerKey(company.PrivateKey);
			var claimRole = new Dictionary<string, object>();
			claimRole.Add(ClaimTypes.Role, "request_auth");

			var token = handler.CreateToken(new SecurityTokenDescriptor()
			{
				Issuer = Convert.ToBase64String(company.PublicKey),
				Audience = "https://api.zpass.io",
				Expires = DateTime.UtcNow.AddDays(2),
				SigningCredentials = new SigningCredentials(signKey, "ZPASS")
			});


			var http = new HttpClient();
			//http.DefaultRequestHeaders.Add("Authorization", "Bearer " + token);

			var headers = new List<KeyValuePair<string, string>>()
			{
				new KeyValuePair<string, string>( "Authorization", "Bearer " + token)
			};

			RequestAuthorizationResponse result = null;

			await HttpPost<RequestAuthorizationResponse>(
				Connection + "/auth/request",
				req,
				headers,
				async (resp) =>
				{
					await Task.CompletedTask;
					result = resp;
					return true;

				},
				async (error) =>
				{
					await Task.CompletedTask;
				});

			return result?.RequestId ?? null;
        }
    }
}
