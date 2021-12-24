using Newtonsoft.Json;

namespace zPassLibrary
{
    public class RequestAuthorizationResponse
    {
        public string Status { get; set; }
        public string RequestId { get; set; }
        public long ExpiresIn { get; set; }
    }

}
