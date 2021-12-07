using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace zPassLibrary
{
    public class BinaryTools
    {
        public static byte[] FromObject(object obj)
        {
            var json = JsonConvert.SerializeObject(obj);
            return Encoding.UTF8.GetBytes(json);
        }

        public static T ToObject<T>(byte[] data)
        {
            var str = Encoding.UTF8.GetString(data);
            return JsonConvert.DeserializeObject<T>(str);
        }

    }
}
