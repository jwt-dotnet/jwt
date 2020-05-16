#if SYSTEMTEXTJSON

using System;
using System.Collections.Generic;
using System.Text.Json;
using JWT;

namespace JWT.Serializers
{
    public sealed class SystemTextJsonSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            return JsonSerializer.Serialize(obj);
        }

        public T Deserialize<T>(string json)
        {
            var data = JsonSerializer.Deserialize<T>(json);

            if (!(data is Dictionary<string, JsonElement> odata)) return data;

            var ndata = new Dictionary<string, object>();
            foreach (var key in odata.Keys)
            {
                var value = odata[key];
                switch (value.ValueKind)
                {
                    case JsonValueKind.String:
                        ndata.Add(key, value.GetString());
                        break;
                    case JsonValueKind.Number:
                        ndata.Add(key, value.GetInt64());
                        break;
                    case JsonValueKind.True:
                        ndata.Add(key, true);
                        break;
                    case JsonValueKind.False:
                        ndata.Add(key, false);
                        break;
                    case JsonValueKind.Undefined:
                    case JsonValueKind.Object:
                    case JsonValueKind.Array:
                    case JsonValueKind.Null:
                        throw new NotSupportedException(nameof(value.ValueKind));
                }
            }

            return ndata is T obj ? obj : data;
        }
    }
}
#endif
