#if MODERN_DOTNET
using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using JWT.Serializers.Converters;

namespace JWT.Serializers
{
    /// <summary>
    /// JSON serializer using Newtonsoft.Json implementation.
    /// </summary>
    public class SystemTextSerializer : IJsonSerializer
    {
        private static readonly JsonSerializerOptions _optionsForSerialize = new JsonSerializerOptions();

        private static readonly JsonSerializerOptions _optionsForDeserialize = new JsonSerializerOptions
        {
            Converters =
            {
                new DictionaryStringObjectJsonConverterCustomWrite()
            }
        };

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public string Serialize(object obj)
        {
            if (obj is null)
                throw new ArgumentNullException(nameof(obj));

            return JsonSerializer.Serialize(obj, _optionsForSerialize);
        }


        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        /// <exception cref="ArgumentException" />
        public object Deserialize(Type type, string json)
        {
            if (type is null)
                throw new ArgumentNullException(nameof(type));
            if (String.IsNullOrEmpty(json))
                throw new ArgumentException(nameof(json));

            return JsonSerializer.Deserialize(json, type, _optionsForDeserialize);
        }

        public string MergeObjects(object obj1, object obj2)
        {
            if (obj1 == null)
            {
                throw new ArgumentNullException(nameof(obj1));
            }

            if (obj2 == null)
            {
                throw new ArgumentNullException(nameof(obj2));
            }

            var jsonNode1 = JsonNode.Parse(Serialize(obj1));
            var jsonNode2 = JsonNode.Parse(Serialize(obj2));

            foreach (var property in jsonNode2.AsObject().ToArray())
            {
                jsonNode2.AsObject().Remove(property.Key);
                jsonNode1[property.Key] = property.Value;
            }

            return jsonNode1.ToJsonString(_optionsForSerialize);
        }
    }
}
#endif
