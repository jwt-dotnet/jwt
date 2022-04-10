#if NEWTONSOFT_JSON
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
        /// <exception cref="ArgumentNullException" />
        public JsonNetSerializer()
            : this(JsonSerializer.CreateDefault())
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="JsonNetSerializer" />
        /// </summary>
        /// <param name="serializer">Internal <see cref="JsonSerializer" /> to use for serialization</param>
        /// <exception cref="ArgumentNullException" />
        public JsonNetSerializer(JsonSerializer serializer) =>
            _serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public string Serialize(object obj)
        {
            if (obj is null)
                throw new ArgumentNullException(nameof(obj));

            var sb = new StringBuilder();
            using var stringWriter = new StringWriter(sb);
            using var jsonWriter = new JsonTextWriter(stringWriter);
            _serializer.Serialize(jsonWriter, obj);
            return sb.ToString();
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

            using var stringReader = new StringReader(json);
            using var jsonReader = new JsonTextReader(stringReader);
            return _serializer.Deserialize(jsonReader, type);
        }
    }
}
#endif