using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1;

namespace zPassLibrary
{
    public class Utils
    {
        private static Lazy<RNGCryptoServiceProvider> RandomServiceProvider = new Lazy<RNGCryptoServiceProvider>(() =>
        {
            return new RNGCryptoServiceProvider();
        });

        public static byte[] GetRandomKey(int keyLength)
        {
            byte[] randomBytes = new byte[keyLength];
            RandomServiceProvider.Value.GetBytes(randomBytes);
            return randomBytes;
        }

        public static byte[] Transform_Aes(byte[] Key, byte[] IV, Func<Aes, ICryptoTransform> transformCallback, Action<CryptoStream> ioCallback)
        {
            byte[] result;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;   
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                //ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                var transform = transformCallback(aesAlg);

                // Create the streams used for encryption.
                using (MemoryStream msTransform = new MemoryStream())
                {
                    using (CryptoStream csTransform = new CryptoStream(msTransform, transform, CryptoStreamMode.Write))
                    {
                        ioCallback(csTransform);
                    }
                    result = msTransform.ToArray();
                }
            }

            // Return the transformed bytes from the memory stream.
            return result;
        }

        public static byte[] Encrypt_Aes(byte[] data, byte[] key)
        {
            var iv = GetRandomKey(16);
            var cipher = Encrypt_Aes(data, key, iv);
            return iv.Concat(cipher).ToArray();
        }

        public static byte[] Encrypt_Aes(string plainText, byte[] Key, byte[] IV)
        {
            var data = System.Text.Encoding.UTF8.GetBytes(plainText);
            return Encrypt_Aes(data, Key, IV);
        }

        public static byte[] Encrypt_Aes(byte[] data, byte[] Key, byte[] IV)
        {
            return Transform_Aes(Key, IV,
            (aesAlg) =>
            {
                return aesAlg.CreateEncryptor();
            },
            (cs) =>
            {
                using (var swEncrypt = new BinaryWriter(cs))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(data);
                }
            });
        }

        public static byte[] Decrypt_Aes(byte[] data, byte[] key)
        {
            return Decrypt_Aes(data.Skip(16).ToArray(), key, data.Take(16).ToArray());
        }

        public static byte[] Decrypt_Aes(byte[] data, byte[] Key, byte[] IV)
        {
            return Transform_Aes(Key, IV,
            (aesAlg) =>
            {
                return aesAlg.CreateDecryptor();
            },
            (cs) =>
            {
                using (var swEncrypt = new BinaryWriter(cs))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(data);
                    cs.FlushFinalBlock();
                }
            });
        }

        public static string Decrypt_AesToString(byte[] data, byte[] Key, byte[] IV)
        {
            var bytePlain = Decrypt_Aes(data, Key, IV);
            return System.Text.Encoding.UTF8.GetString(bytePlain);
        }


        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var curve = ECNamedCurveTable.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var secureRandom = new SecureRandom();
            var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);
            var keyPair = generator.GenerateKeyPair();

            return keyPair;
        }


        public static byte[] PBKDF2(string password, byte[] salt, int iterations)
        {
            Rfc2898DeriveBytes k = new Rfc2898DeriveBytes(password, salt, iterations);
            return k.GetBytes(32);
        }
        /*
        public static byte[] GetBytes(string str)
        {
            byte[] bytes = new byte[str.Length * sizeof(char)];
            System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
            return bytes;
        }

        public static string GetString(byte[] bytes)
        {
            char[] chars = new char[bytes.Length / sizeof(char)];
            System.Buffer.BlockCopy(bytes, 0, chars, 0, bytes.Length);
            return new string(chars);
        }
        */

        public static byte[] Sign(byte[] data, byte[] privKey)
        {
            var ecParams = ECNamedCurveTable.GetByName("secp256k1");

            var privKeyInt = new Org.BouncyCastle.Math.BigInteger(+1, privKey);

            ECDomainParameters domainParameters = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
            var privkeyParam = new ECPrivateKeyParameters(privKeyInt, domainParameters);

            var signer = SignerUtilities.GetSigner("SHA256withECDSA");

            signer.Init(true, privkeyParam);

            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public static string GenerateQrCodeInfo(Entity entity, string type, string[] request, string url, string id)
        {
            var qrInfo = new QrCodeInfo()
            {
                DateIssued = DateTime.UtcNow,
                Issuer = entity.PublicKey,
                IssuerName = entity.Identity,
                Request = request,
                Id = id,
                Url = url,
                Type = type
            };
            var payload = BinaryTools.FromObject(qrInfo);
            var sign = Sign(payload, entity.PrivateKey);

            return $"qrcodeinfo://{Convert.ToBase64String(payload)}.{Convert.ToBase64String(sign)}";
        }

        public static (QrCodeInfo qri, byte[] payload, byte[] signature) ReadQrCodeInfo(string input)
        {
            if (input.StartsWith("qrcodeinfo://"))
            {
                var split = input.Substring(13).Split('.');
                var payload = Convert.FromBase64String(split[0]);
                var signature = Convert.FromBase64String(split[1]);
                var qci = JsonConvert.DeserializeObject<QrCodeInfo>(UTF8Encoding.UTF8.GetString(payload));
                if( zPassLibrary.Utils.Verify(payload, signature, qci.Issuer))
                {
                    //test url if valid
                    if (Uri.TryCreate(qci.Url, UriKind.Absolute, out Uri uri))
                    {
                        return (qci, payload, signature);
                    }
                }
            }

            throw new Exception("Invalid Qr Code");
        }

        public static byte[] SignObject( object obj, byte[] privKey )
        {
            var s = JsonConvert.SerializeObject(obj);
            return Sign(Encoding.UTF8.GetBytes(s), privKey);
        }

        private static Lazy<X9ECParameters> _ECParams = new Lazy<X9ECParameters>(() =>
        {
            return ECNamedCurveTable.GetByName("secp256k1");
        });

        private static Lazy<ECDomainParameters> _DomainParameters = new Lazy<ECDomainParameters>(() =>
        {
           return new ECDomainParameters(_ECParams.Value.Curve, _ECParams.Value.G, _ECParams.Value.N, _ECParams.Value.H, _ECParams.Value.GetSeed());
        });

        private static Lazy<ISigner> _Signer = new Lazy<ISigner>(() =>
        {
            return SignerUtilities.GetSigner("SHA256withECDSA");
        });

        public static bool Verify(byte[] data, byte[] signature, byte[] pubKey)
        {
            var spanPubKey = (Span<byte>)pubKey;
            var pubKeyParam = new ECPublicKeyParameters(_ECParams.Value.Curve.DecodePoint( spanPubKey.Slice(5).ToArray() ), _DomainParameters.Value);

            _Signer.Value.Init(false, pubKeyParam);
            _Signer.Value.BlockUpdate(data, 0, data.Length);
            return _Signer.Value.VerifySignature(signature);
        }

        public static bool ByteArrayCompare(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
        }

        public static DateTime FromUnixTimeStamp(long time)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddSeconds(time);
        }


    }
}
