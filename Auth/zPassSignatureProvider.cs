using Microsoft.IdentityModel.Tokens;
using System.Linq;

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

        public override bool Verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength)
        {
            return Verify(input.Skip(inputOffset).Take(inputLength).ToArray(), signature);
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            var key = Key as zPassSecurityKey;
            var result = Utils.Verify(input, signature, key.PublicKey);
            return result;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
