[![NuGet](https://img.shields.io/nuget/v/jwt.svg)](https://www.nuget.org/packages/JWT)[![NuGet Pre](https://img.shields.io/nuget/vpre/jwt.svg)](https://www.nuget.org/packages/JWT)[![Build status](https://ci.appveyor.com/api/projects/status/dgcpnsa647u90pnh/branch/master?svg=true)](https://ci.appveyor.com/project/abatishchev/jwt/branch/master)

# Jwt.Net, a JWT (JSON Web Token) implementation for .NET

This library supports generating and decoding [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10).

## Installation
Package is avaliable via [NuGet](https://nuget.org/packages/JWT). Or you can download and compile it yourself.

## Supported .NET Framework versions:
- .NET 4.6.0
- .NET Standard 1.3

## Usage
### Creating (encoding) token

```csharp
var payload = new Dictionary<string, object>
{
    { "claim1", 0 },
    { "claim2", "claim2-value" }
};
var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
IJsonSerializer serializer = new JsonNetSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

var token = encoder.Encode(payload, secret);
Console.WriteLine(token);
```

## Or using the fluent builder API

```csharp
var token = new JwtBuilder().
    .SetAlgorithm(new HMACSHA256Algorithm())
    .SetSecret("GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk")
    .AddClaim(PublicClaimsNames.ExpirationTime, DateTime.UtcNow.AddHours(5).ToString())
    .Build();

Console.WriteLine(token);
```

The output would be:

>eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s

### Parsing (decoding) and verifying token

```csharp
var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
try
{
    IJsonSerializer serializer = new JsonNetSerializer();
    IDateTimeProvider provider = new UtcDateTimeProvider();
    IJwtValidator validator = new JwtValidator(serializer, provider);
    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder);
    
    var json = decoder.Decode(token, secret, verify: true);
    Console.WriteLine(json);
}
catch (TokenExpiredException)
{
    Console.WriteLine("Token has expired");
}
catch (SignatureVerificationException)
{
    Console.WriteLine("Token has invalid signature");
}
```

## Or using the fluent builder API

```csharp
var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
try
{
    var json = new JwtBuilder()
        .SetSecret(secret)
        .MustVerify()
        .Decode(token);                    
    Console.WriteLine(json);
}
catch (TokenExpiredException)
{
    Console.WriteLine("Token has expired");
}
catch (SignatureVerificationException)
{
    Console.WriteLine("Token has invalid signature");
}
```

The output would be:

>{ "claim1": 0, "claim2": "claim2-value" }

You can also deserialize the JSON payload directly to a .NET type with `Decode<T>`:

```csharp
var payload = new JwtBuilder()
        .SetSecret(secret)
        .MustVerify()
        .Decode<IDictionary<string, object>>(token);     
Console.WriteLine(payload["claim2"]);
```

The output would be:
    
>claim2-value

#### Set token expiration

As described in the [JWT RFC](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4), the `exp` "claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing." If an `exp` claim is present and is prior to the current time the token will fail verification. The exp (expiry) value must be specified as the number of seconds since 1/1/1970 UTC.

```csharp
IDateTimeProvider provider = new UtcDateTimeProvider();
var now = provider.GetNow();

var unixEpoch = JwtValidator.UnixEpoch; // 1970-01-01 00:00:00 UTC
var secondsSinceEpoch = Math.Round((now - unixEpoch).TotalSeconds);

var payload = new Dictionary<string, object>
{
    { "exp", secondsSinceEpoch }
};
var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
var token = encoder.Encode(payload, secret);

var json = decoder.Decode(token, secret); // throws TokenExpiredException
```

### Custom JSON serializer

By default JSON serialization is performed by JsonNetSerializer implemented using [Json.Net](https://www.json.net). To use a different one, implement the `IJsonSerializer` interface:

```csharp
public class CustomJsonSerializer : IJsonSerializer
{
    public string Serialize(object obj)
    {
        // Implement using favorite JSON serializer
    }

    public T Deserialize<T>(string json)
    {
        // Implement using favorite JSON serializer
    }
}
```

And then pass this serializer as a dependency to JwtEncoder constructor:

```csharp
IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
IJsonSerializer serializer = new CustomJsonSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
```

### Custom JSON serialization settings with the default JsonNetSerializer

As mentioned above, the default JSON serialization is done by `JsonNetSerializer`. You can define your own custom serialization settings as follows:

```csharp
JsonSerializer customJsonSerializer = new JsonSerializer
{
    // All json keys start with lowercase characters instead of the exact casing of the model/property, e.g. fullName
    ContractResolver = new CamelCasePropertyNamesContractResolver(), 
    
    // Nice and easy to read, but you can also use Formatting.None to reduce the payload size
    Formatting = Formatting.Indented,
    
    // The most appropriate datetime format.
    DateFormatHandling = DateFormatHandling.IsoDateFormat,
    
    // Don't add keys/values when the value is null.
    NullValueHandling = NullValueHandling.Ignore,
    
    // Use the enum string value, not the implicit int value, e.g. "red" for enum Color { Red }
    Converters.Add(new StringEnumConverter())
};
IJsonSerializer serializer = new JsonNetSerializer(customJsonSerializer);
```