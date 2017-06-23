using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWT.Serializers
{
    /// <summary>
    /// JSON serializer using Newtonsoft.Json implementation.
    /// </summary>
    public sealed class JsonNetSerializer : IJsonSerializer
    {
        private readonly JsonSerializer _serializer;

        /// <summary>
        /// Creates a new instance of <see cref="JsonNetSerializer" />.
        /// </summary>
        /// <remarks>Uses <see cref="JsonSerializer.CreateDefault()" /> as internal serializer.</remarks>
        public JsonNetSerializer()
            : this(JsonSerializer.CreateDefault())
        {

        }

        /// <summary>
        /// Creates a new instance of <see cref="JsonNetSerializer" />.
        /// </summary>
        /// <param name="serializer">Internal <see cref="JsonSerializer" /> to use for serialization.</param>
        public JsonNetSerializer(JsonSerializer serializer)
        {
            _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
        }

        /// <summary>
        /// Serialize the given object.
        /// </summary>
        /// <param name="obj">The object to serialize.</param>
        /// <returns></returns>
        public string Serialize(object obj)
        {
            return JObject.FromObject(obj, _serializer).ToString(Formatting.None);
        }

        /// <summary>
        /// Deserialize the given string.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the string to.</typeparam>
        /// <param name="json">The JSON to be deserialized.</param>
        /// <returns></returns>
        public T Deserialize<T>(string json)
        {
            return JObject.Parse(json).ToObject<T>();
        }
    }
}