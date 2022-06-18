#if SYSTEM_TEXT_JSON
using System;
using System.Text.Json;
using JWT.Serializers.Converters;

namespace JWT.Serializers
{
    /// <summary>
    /// JSON serializer using Newtonsoft.Json implementation.
    /// </summary>
    public class SystemTextSerializer : IJsonSerializer
    {
        private static readonly JsonSerializerOptions _options = new JsonSerializerOptions
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

            return JsonSerializer.Serialize(obj, _options);
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

            return JsonSerializer.Deserialize(json, type, _options);
        }
    }
}
#endif
