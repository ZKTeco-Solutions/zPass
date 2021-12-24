using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary
{
    public class zPassCryptoProvider : ICryptoProvider
    {
        public object Create(string algorithm, params object[] args)
        {
            throw new NotImplementedException();
        }

        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {
            return algorithm == "ZPASS";
        }

        public void Release(object cryptoInstance)
        {
            if (cryptoInstance is IDisposable disposableObject)
                disposableObject.Dispose();
        }
    }
}
