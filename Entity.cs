using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace zPassLibrary
{
    public enum EnumEntityType
    {
        Generic = 0,
        Person = 1,
        PrivateOrganization = 2,
        Government = 3,
        Software = 4,
        Device = 5,
        Proxy = 6
    }
        

    public class Entity
    {
        public byte[] PrivateKey { get; private set; }
        public byte[] PublicKey { get; private set; }
        public EnumEntityType EntityType { get; private set; }
        public string Identity { get; private set; }

        public static Entity CreatePersonFromSecret(string firstName, string lastName, string secret)
        {
            var bip39 = new dotnetstandard_bip39.BIP39();
            var entropy = bip39.MnemonicToEntropy(secret, dotnetstandard_bip39.BIP39Wordlist.English);
            var sha = SHA256.Create();
            var privKey = sha.ComputeHash(entropy);
            return new Entity(EnumEntityType.Person, $"{firstName} {lastName}", privKey);
        }

        public static Entity CreateNew(EnumEntityType type, string identity)
        {
            var keyPair = Utils.GenerateKeyPair();
            var privKey = (keyPair.Private as ECPrivateKeyParameters).D.ToByteArrayUnsigned();

            return new Entity(type, identity, privKey);

            /*
            var pubKey = (keyPair.Public as ECPublicKeyParameters).Q.GetEncoded();

            var entity = new Entity();

            var arrID = System.Text.Encoding.UTF8.GetBytes(identity);

            var crc32 = Force.Crc32.Crc32CAlgorithm.Compute(arrID);

            entity.Identity = identity;
            entity.PrivateKey = privKey;
            entity.EntityType = type;
            //public key : type crc32 pubkey
            entity.PublicKey = new List<byte[]> { new byte[] { (byte)type }, BitConverter.GetBytes(crc32), pubKey }.SelectMany(x=>x).ToArray();

            return entity;*/
        }

        public Entity (EnumEntityType type, string identity, byte[] privateKey)
        {
            var arrID = System.Text.Encoding.UTF8.GetBytes(identity);
            var crc32 = Force.Crc32.Crc32CAlgorithm.Compute(arrID);

            var ecParams = ECNamedCurveTable.GetByName("secp256k1");
            ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
            /*
            var pubX = new Org.BouncyCastle.Math.BigInteger(+1, x);
            var pubY = new Org.BouncyCastle.Math.BigInteger(+1, y);
            var ecPoint = ecParams.Curve.CreatePoint(pubX, pubY);
            */
            var d = new BigInteger(privateKey);
            var ecPoint = domainParameters.G.Multiply(d);

            var pubKeyParam = new ECPublicKeyParameters(ecPoint, domainParameters);

            var encoded = pubKeyParam.Q.GetEncoded();

            this.PrivateKey = privateKey;
            this.PublicKey = new List<byte[]> { new byte[] { (byte)type }, BitConverter.GetBytes(crc32), pubKeyParam.Q.GetEncoded()}.SelectMany(z => z).ToArray();
            this.Identity = identity;
            this.EntityType = type;
        }

        public static bool VerifyPublicKeyIdentity(byte[] publicKey, string identity)
        {
            var byteCompany = System.Text.Encoding.UTF8.GetBytes(identity);
            var crc32 = Force.Crc32.Crc32CAlgorithm.Compute(byteCompany);

            if (BitConverter.ToUInt32(publicKey, 1) != crc32)
                return false;
            else
                return true;
        }

    }
}

