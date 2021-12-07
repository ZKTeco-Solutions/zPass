using System;
using System.Collections.Generic;
using System.Text;

using System.IO;
using Org.BouncyCastle.Crypto.Paddings;
using System.Linq;
using System.Text;

namespace zPassLibrary
{
    public class MessageFormatter
    {
        public enum PropType
        {
            Byte = 0,
            Short = 1,
            Int = 2,
            Long = 3,
            String = 4,
            Double = 5,
            Boolean = 6,
            DateTime = 7,
            Array = 8,
            Enum = 9
        }

        public static T ToObject<T>(byte[] data) where T : new()
        {
            var properties = typeof(T).GetProperties();
            var obj = new T();

            using (var ms = new MemoryStream(data))
            {
                var reader = new BinaryReader(ms);

                while (true)
                {
                    int propNameLength = 0;
                    try
                    {
                        propNameLength = reader.ReadByte();
                    }
                    catch (EndOfStreamException)
                    {
                        break;
                    }

                    var bytePropName = reader.ReadBytes(propNameLength);
                    var prop = properties.Where(x => x.Name == System.Text.Encoding.ASCII.GetString(bytePropName)).First();


                    Func<PropType, object> readValue = new Func<PropType, object>((t) =>
                    {
                        switch (t)
                        {
                            case PropType.Byte:
                                return reader.ReadByte();
                            case PropType.Boolean:
                                return reader.ReadBoolean();
                            case PropType.Short:
                                return reader.ReadInt16();
                            case PropType.Int:
                            case PropType.Enum:
                                return reader.ReadInt32();
                            case PropType.Long:
                                return reader.ReadInt64();
                            case PropType.DateTime:
                                return new DateTime( reader.ReadInt64());
                            case PropType.String:
                                var strLen = reader.ReadInt32();
                                var byteStr = reader.ReadBytes(strLen);
                                return System.Text.Encoding.UTF8.GetString(byteStr);
                            default:
                                throw new NotSupportedException();
                        }
                    });

                    PropType pt = (PropType)reader.ReadByte();

                    if (pt == PropType.Array)
                    {
                        var list = new List<object>();
                        PropType t = (PropType)reader.ReadByte();
                        var arrLen = reader.ReadInt32();
                        for (int i = 0; i < arrLen; i++)
                        {
                            list.Add(readValue(t));
                        }
                        switch (t)
                        {
                            case PropType.Byte:
                                prop.SetValue(obj, list.Select(x => (byte)x).ToArray());
                                break;
                            case PropType.Boolean:
                                prop.SetValue(obj, list.Select(x => (bool)x).ToArray());
                                break;
                            case PropType.Short:
                                prop.SetValue(obj, list.Select(x => (short)x).ToArray());
                                break;
                            case PropType.Int:
                            case PropType.Enum:
                                prop.SetValue(obj, list.Select(x => (int)x).ToArray());
                                break;
                            case PropType.Long:
                                prop.SetValue(obj, list.Select(x => (long)x).ToArray());
                                break;
                            case PropType.String:
                                prop.SetValue(obj, list.Select(x => (string)x).ToArray());
                                break;
                            default:
                                throw new NotSupportedException();
                        }
                    }
                    else
                    {
                        prop.SetValue(obj, readValue(pt));
                    }
                }
            }

            return obj;
        }

        public static byte[] ToArray(object data)
        {
            var properties = data.GetType().GetProperties();
            byte[] result = null;

            using (var ms = new MemoryStream())
            {
                var writer = new BinaryWriter(ms);

                Action<Type> writeType = new Action<Type>((t) =>
                {
                    if (t == typeof(byte))
                        writer.Write((byte)PropType.Byte);
                    else if (t == typeof(bool))
                        writer.Write((byte)PropType.Boolean);
                    else if (t == typeof(short))
                        writer.Write((byte)PropType.Short);
                    else if (t == typeof(int))
                        writer.Write((byte)PropType.Int);
                    else if (t == typeof(long))
                        writer.Write((byte)PropType.Long);
                    else if (t == typeof(string))
                        writer.Write((byte)PropType.String);
                    else if (t == typeof(DateTime))
                        writer.Write((byte)PropType.DateTime);
                    else if( t.BaseType == typeof(System.Enum))
                    {
                        writer.Write((byte)PropType.Enum);
                    }
                    else
                    {
                        throw new NotSupportedException();
                    }
                });

                Action<Type, object> write = new Action<Type, object>((t, obj) =>
                {
                    if (t == typeof(byte))
                        writer.Write((byte)obj);
                    else if (t == typeof(bool))
                        writer.Write((bool)obj);
                    else if (t == typeof(short))
                        writer.Write((short)obj);
                    else if (t == typeof(int))
                        writer.Write((int)obj);
                    else if (t == typeof(long))
                        writer.Write((long)obj);
                    else if (t == typeof(DateTime))
                        writer.Write(((DateTime)obj).Ticks);
                    else if (t == typeof(string))
                    {
                        var byteStr = System.Text.Encoding.UTF8.GetBytes((string)obj);
                        writer.Write((int)byteStr.Length);
                        writer.Write(byteStr);
                    }
                    else if(t.BaseType == typeof(System.Enum))
                    {
                        writer.Write((int)obj);
                    }
                    else
                    {
                        throw new NotSupportedException();
                    }

                });

                foreach (var prop in properties)
                {
                    var byteName = System.Text.Encoding.ASCII.GetBytes(prop.Name);
                    writer.Write((byte)byteName.Length);
                    writer.Write(byteName);

                    var obj = prop.GetValue(data);
                    if (obj is Array)
                    {
                        writer.Write((byte)PropType.Array);
                        writeType(((Array)obj).GetType().GetElementType());
                        writer.Write((int)((Array)obj).Length);

                        foreach (object elem in (Array)obj)
                        {
                            write(elem.GetType(), elem);
                        }
                    }
                    else
                    {
                        writeType(prop.PropertyType);
                        write(prop.PropertyType, obj);
                    }
                }

                result = ms.ToArray();
            }

            return result;

        }

        public class SignaturePair
        {
            public SignaturePair(byte[] pubKey, byte[] sig)
            {
                PublicKey = pubKey;
                Signature = sig;
            }

            public byte[] PublicKey { get; set; }
            public byte[] Signature { get; set; }
        }

        public class SignedData
        {
            public string Name { get; set; }
            public List<SignaturePair> Signatures { get; set; } = new List<SignaturePair>();
            public byte[] Data { get; set; }
        }

        public static byte[] EncodeSignedData(byte[] data, string name, SignaturePair[] signatures)
        {
            byte[] version = new byte[] { 1 };
            var byteName = System.Text.Encoding.UTF8.GetBytes(name);
            var nameSize = BitConverter.GetBytes((short)byteName.Length);
            var sigPairCount = BitConverter.GetBytes((int)signatures.Length);

            List<byte[]> arrSignatures = new List<byte[]>();

            foreach (var sp in signatures)
            {
                var sigSize = new byte[] { (byte)sp.Signature.Length };

                var parsedPubKey = sp.PublicKey == null ? new byte[0] : sp.PublicKey;
                var pubKeySize = new byte[] { (byte)parsedPubKey.Length };

                arrSignatures.Add(pubKeySize);
                arrSignatures.Add(parsedPubKey);
                arrSignatures.Add(sigSize);
                arrSignatures.Add(sp.Signature);
            }

            return new List<byte[]> {   version, 
                                        nameSize, 
                                        byteName, 
                                        sigPairCount, 
                                        arrSignatures.SelectMany( x=> x).ToArray(),
                                        data 
                                    }.SelectMany(x => x).ToArray();
        }

        public static SignedData DecodeSignedData(byte[] data)
        {
            SignedData result = new SignedData();

            using (var ms = new MemoryStream(data))
            {
                var reader = new BinaryReader(ms);
                var version = reader.ReadByte();

                var szName = reader.ReadInt16();
                result.Name = Encoding.UTF8.GetString(reader.ReadBytes(szName));

                var pairCount = reader.ReadInt32();

                for (int i = 0; i < pairCount; i++)
                {
                    var pubKeySize = reader.ReadByte();
                    var pubKey = reader.ReadBytes(pubKeySize);

                    var sigSize = reader.ReadByte();
                    var signature = reader.ReadBytes(sigSize);

                    result.Signatures.Add(new SignaturePair (pubKey, signature));
                }

                result.Data = reader.ReadBytes((int)(ms.Length - ms.Position));
            }

            return result;

        }

    }
}
