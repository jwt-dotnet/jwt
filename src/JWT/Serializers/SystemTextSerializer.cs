#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
using System;
using System.Text.Json;
using JWT.Serializers.Converters;
#if NET8_0_OR_GREATER
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization.Metadata;
#endif

namespace JWT.Serializers
{
    /// <summary>
    /// JSON serializer using System.Text.Json implementation.
    /// </summary>
    public class SystemTextSerializer : IJsonSerializer
    {
#if NET8_0_OR_GREATER
        // Same guard as JsonSerializerOptions.Default: the System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault
        // feature switch is false by default in trimmed and Native AOT apps, so the reflection branch is removed there.
        private const string ReflectionJustification = "Reflection is used only when JsonSerializer.IsReflectionEnabledByDefault is true, as with JsonSerializerOptions.Default.";

        private static readonly JsonSerializerOptions _defaultOptionsForSerialize = CreateOptions(null, forDeserialize: false);
        private static readonly JsonSerializerOptions _defaultOptionsForDeserialize = CreateOptions(null, forDeserialize: true);

        private readonly JsonSerializerOptions _optionsForSerialize;
        private readonly JsonSerializerOptions _optionsForDeserialize;

        /// <summary>
        /// Creates a new instance with the default options.
        /// </summary>
        /// <remarks>
        /// When reflection-based serialization is disabled (trimmed and Native AOT apps), only the library's own types
        /// and common claim value types are supported. Use the constructor that takes JsonSerializerOptions
        /// to supply metadata for custom types.
        /// </remarks>
        public SystemTextSerializer()
        {
            _optionsForSerialize = _defaultOptionsForSerialize;
            _optionsForDeserialize = _defaultOptionsForDeserialize;
        }

        /// <summary>
        /// Creates a new instance with the supplied options.
        /// </summary>
        /// <param name="options">
        /// The options to use, e.g. MyJsonSerializerContext.Default.Options of a source-generated
        /// JsonSerializerContext for custom payload types. The options are copied, not modified.
        /// </param>
        /// <remarks>
        /// Metadata for the library's own types is appended to the TypeInfoResolver of the options.
        /// If no resolver is set, the same resolver as the parameterless constructor is used.
        /// </remarks>
        /// <exception cref="ArgumentNullException" />
        public SystemTextSerializer(JsonSerializerOptions options)
        {
            if (options is null)
                throw new ArgumentNullException(nameof(options));

            _optionsForSerialize = CreateOptions(options, forDeserialize: false);
            _optionsForDeserialize = CreateOptions(options, forDeserialize: true);
        }
#else
        private static readonly JsonSerializerOptions _optionsForSerialize = new JsonSerializerOptions();

        private static readonly JsonSerializerOptions _optionsForDeserialize = new JsonSerializerOptions
        {
            Converters =
            {
                new DictionaryStringObjectJsonConverterCustomWrite()
            }
        };
#endif

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException" />
        public string Serialize(object obj)
        {
            if (obj is null)
                throw new ArgumentNullException(nameof(obj));

#if NET8_0_OR_GREATER
            return JsonSerializer.Serialize(obj, _optionsForSerialize.GetTypeInfo(typeof(object)));
#else
            return JsonSerializer.Serialize(obj, _optionsForSerialize);
#endif
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

#if NET8_0_OR_GREATER
            return JsonSerializer.Deserialize(json, _optionsForDeserialize.GetTypeInfo(type));
#else
            return JsonSerializer.Deserialize(json, type, _optionsForDeserialize);
#endif
        }

#if NET8_0_OR_GREATER
        private static JsonSerializerOptions CreateOptions(JsonSerializerOptions source, bool forDeserialize)
        {
            var options = source is null ? new JsonSerializerOptions() : new JsonSerializerOptions(source);
            options.TypeInfoResolver = source?.TypeInfoResolver is { } resolver ?
                JsonTypeInfoResolver.Combine(resolver, JwtNetJsonSerializerContext.Default) :
                CreateDefaultTypeInfoResolver();

            if (forDeserialize)
                options.Converters.Add(new DictionaryStringObjectJsonConverterCustomWrite());

            options.MakeReadOnly();
            return options;
        }

        [UnconditionalSuppressMessage("Trimming", "IL2026", Justification = ReflectionJustification)]
        [UnconditionalSuppressMessage("AOT", "IL3050", Justification = ReflectionJustification)]
        private static IJsonTypeInfoResolver CreateDefaultTypeInfoResolver()
        {
            if (JsonSerializer.IsReflectionEnabledByDefault)
                return new DefaultJsonTypeInfoResolver();

            return JwtNetJsonSerializerContext.Default;
        }
#endif
    }
}
#endif
