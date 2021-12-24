namespace zPassLibrary
{
    public class RequestAuthorizationParameter
    {
        public string ClientId { get; set; }
        public string Scope { get; set; }
        public string RedirectUri { get; set; }
        public string State { get; set; }
        public string SoftwareName { get; set; }
        public string OrganizationName { get; set; }

    }

}
