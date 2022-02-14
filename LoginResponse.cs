using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary
{
    public class LoginResponse
    {
        public byte[] UserId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string RequestId { get; set; }
        public byte[] RequestSignature { get; set; }
        public DateTime IssuedDate { get; set; }
        public string Otp { get; set; }
    }
}
