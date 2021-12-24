using Newtonsoft.Json;

namespace zPassLibrary
{
    public class AuthorizeParameter
    {
        public string SoftwareId { get; set; }
        public string Scope { get; set; }
        public string WebTokenId { get; set; }
    }

}
