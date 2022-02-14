using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.JsonWebTokens;
using System;

namespace zPassLibrary.Auth
{
    public class zPassAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public delegate bool ValidatorDelegate(string token, JsonWebToken jwt);
        public ValidatorDelegate Validator { get; set; } = null;
    }
}
