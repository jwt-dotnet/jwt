using System;
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace JWT.Serializers
{
    /// <summary>
    /// JSON serializer using Newtonsoft.Json implementation.
    /// </summary>
    public sealed class JsonNetSerializer : IJsonSerializer
    {
        private readonly JsonSerializer _serializer;

        /// <summary>
        /// Creates a new instance of <see cref="JsonNetSerializer" />
        /// </summary>
        /// <remarks>Uses <see cref="JsonSerializer.CreateDefault()" /> as internal serializer</remarks>
        public JsonNetSerializer()
            : this(JsonSerializer.CreateDefault())
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="JsonNetSerializer" />
        /// </summary>
        /// <param name="serializer">Internal <see cref="JsonSerializer" /> to use for serialization</param>
        public JsonNetSerializer(JsonSerializer serializer) =>
            _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));

        /// <inheritdoc />
        public string Serialize(object obj)
        {
            var sb = new StringBuilder();
            using var stringWriter = new StringWriter(sb);
            using var jsonWriter = new JsonTextWriter(stringWriter);
            _serializer.Serialize(jsonWriter, obj);
            return sb.ToString();
        }

        /// <inheritdoc />
        public T Deserialize<T>(string json)
        {
            using var stringReader = new StringReader(json);
            using var jsonReader = new JsonTextReader(stringReader);
            return _serializer.Deserialize<T>(jsonReader);
        }
    }
}