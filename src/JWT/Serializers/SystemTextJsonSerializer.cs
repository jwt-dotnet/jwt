#if SYSTEMTEXTJSON

using System;
using System.Collections.Generic;
using System.Text.Json;

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

            // when deserializing a Dictionary<string, object>
            // System.Text.Json create JsonElement objects for every value of the dictionary
            // but application will expect to have native basic types (not a JsonElement class)
            if (!(data is Dictionary<string, object> odata)) return data;

            // we need to create another dictionary and fill it with the real values
            // only basic types are supported (no complex object allowed, throw a NotSupportedException in these cases)
            // number always converted to long (int64) basic type
            var ndata = new Dictionary<string, object>();
            foreach (var key in odata.Keys)
            {
                var value = (JsonElement)odata[key];
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
                    default:
                        throw new NotSupportedException(nameof(value.ValueKind));
                }
            }

            return ndata is T obj ? obj : data;
        }
    }
}
#endif
