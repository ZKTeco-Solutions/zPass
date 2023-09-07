using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary.Auth
{
    public class zPassSecurityKey : AsymmetricSecurityKey
    {
        public byte[] PrivateKey { get; private set; } = null;
        public byte[] PublicKey { get; private set; } = null;

        public static zPassSecurityKey CreateSignerKey( byte[] priv)
        {
            var key = new zPassSecurityKey();
            key.PrivateKey = priv;
            key.CryptoProviderFactory.CustomCryptoProvider = new zPassCryptoProvider();

            return key;
        }

        public static zPassSecurityKey CreateVerifierKey( byte[] pub)
        {
            var key = new zPassSecurityKey();
            key.PublicKey = pub;

            key.CryptoProviderFactory.CustomCryptoProvider = new zPassCryptoProvider();

            return key;
        }

        [Obsolete]
        public override bool HasPrivateKey => throw new NotImplementedException();

        public override PrivateKeyStatus PrivateKeyStatus => 
            PrivateKey != null ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

        public override int KeySize => throw new NotImplementedException();
    }
}
