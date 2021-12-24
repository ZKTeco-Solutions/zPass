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
        public string AccessToken { get; set; }
        public string TokenType { get; set; } = "Bearer";
        public long ExpiresIn { get; set; }
    }

}
