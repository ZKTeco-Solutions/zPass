using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary.Auth
{
    public class zPassCryptoProvider : ICryptoProvider
    {
        public object Create(string algorithm, params object[] args)
        {
            if (algorithm == "ZPASS"
                        && args[0] is zPassSecurityKey key)
            {
                return new zPassSignatureProvider(key, algorithm);
            }

            throw new NotSupportedException();
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
