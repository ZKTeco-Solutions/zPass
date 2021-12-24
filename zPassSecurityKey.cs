using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary
{
    public class zPassSecurityKey : AsymmetricSecurityKey
    {
        public override bool HasPrivateKey => throw new NotImplementedException();

        public override PrivateKeyStatus PrivateKeyStatus => throw new NotImplementedException();

        public override int KeySize => throw new NotImplementedException();
    }
}
