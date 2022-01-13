using Microsoft.AspNetCore.Authentication;
using System;

namespace zPassLibrary
{
    public class zPassAuthenticationSchemeOptions : AuthenticationSchemeOptions
    {
        public delegate bool ValidatorDelegate(string token);
        public ValidatorDelegate Validator { get; set; } = null;
    }
}
