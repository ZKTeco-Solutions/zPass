using Microsoft.IdentityModel.Tokens;

namespace zPassLibrary.Auth
{
    public class zPassSignatureProvider : SignatureProvider
    {
        public zPassSignatureProvider(zPassSecurityKey key, string algorithm)
               : base(key, algorithm) { }

        public override byte[] Sign(byte[] input)
        {
            var key = Key as zPassSecurityKey;
            return Utils.Sign(input, key.PrivateKey);
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            var key = Key as zPassSecurityKey;
            return Utils.Verify(input, signature, key.PublicKey);
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
