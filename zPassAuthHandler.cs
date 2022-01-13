using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Linq;

namespace zPassLibrary
{
    public class zPassAuthHandler : AuthenticationHandler<zPassAuthenticationSchemeOptions>
    {
        public zPassAuthHandler(
                  IOptionsMonitor<zPassAuthenticationSchemeOptions> options,
                  ILoggerFactory logger,
                  UrlEncoder encoder,
                  ISystemClock clock)
                  : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // validation comes in here
            if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
            {
                return Task.FromResult(AuthenticateResult.Fail("Header Not Found."));
            }

            if( Options.Validator == null)
            {
                return Task.FromResult(AuthenticateResult.Fail("Validator not set"));
            }

            var header = Request.Headers[HeaderNames.Authorization].ToString();

            if (header.IndexOf("Bearer ") == 0 )
            {
                var token = header.Substring(7);


                var valid = Options.Validator(token);


                if( valid )
                {
                    var handler = new JsonWebTokenHandler();
                    var jsonToken = handler.ReadJsonWebToken(token);

                    // generate AuthenticationTicket from the Identity
                    // and current authentication scheme
                    var claimsIdentity = new ClaimsIdentity(jsonToken.Claims,
                                nameof(zPassAuthHandler));
                   

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);
                    

                    // pass on the ticket to the middleware
                    return Task.FromResult(AuthenticateResult.Success(ticket));
                }
                else
                {
                    return Task.FromResult(AuthenticateResult.Fail("Invalid Token"));
                }
            }

            return Task.FromResult(AuthenticateResult.Fail("Bearer Token Not Found"));
        }
    }
}
