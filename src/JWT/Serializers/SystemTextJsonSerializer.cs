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
            // Implement using favorite JSON serializer
            return JsonSerializer.Serialize(obj);
        }

        public T Deserialize<T>(string json)
        {
            // Implement using favorite JSON serializer
            var data = JsonSerializer.Deserialize<T>(json);

            if (data is Dictionary<string, object> odata)
            {
                var ndata = new Dictionary<string, object>();
                foreach (var key in odata.Keys)
                {
                    var value = (JsonElement)odata[key];
                    switch (value.ValueKind)
                    {
                        case JsonValueKind.Undefined:
                            break;
                        case JsonValueKind.Object:
                            break;
                        case JsonValueKind.Array:
                            break;
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
                        case JsonValueKind.Null:
                            break;
                    }
                }

                if (ndata is T obj)
                    return obj;
            }

            return data;
        }
    }
}
#endif
