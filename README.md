[![Build status](https://ci.appveyor.com/api/projects/status/dgcpnsa647u90pnh/branch/master?svg=true)](https://ci.appveyor.com/project/abatishchev/jwt/branch/master)

# Jwt.Net, a JWT (JSON Web Token) implementation for .NET

This library supports generating and decoding [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10).

## Installation
Package is avaliable via [NuGet](https://nuget.org/packages/JWT). Or you can download and compile it yourself.

## Supported .NET Framework versions
As of version 2.0, the lowest Supported version is 4.6.1

## Usage
### Creating (Encoding) Tokens

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

Output will be:

>eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s

### Parsing (Decoding) and Verifying Tokens

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

Output will be:

>{ "claim1": 0, "claim2": "claim2-value" }

You can also deserialize the JSON payload directly to a .NET type with `DecodeToObject<T>`:

```csharp
var payload = decoder.DecodeToObject<IDictionary<string, object>>(token, secret);
Console.WriteLine(payload["claim2"]);
```

Output will be:
    
>claim2-value

#### exp claim

As described in the [JWT RFC](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4), the `exp` "claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing." If an `exp` claim is present and is prior to the current time the token will fail verification. The exp (expiry) value must be specified as the number of seconds since 1/1/1970 UTC.

```csharp
IDateTimeProvider provider = new UtcDateTimeProvider();
var now = provider.GetNow();

var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // or use JwtValidator.UnixEpoch
var secondsSinceEpoch = Math.Round((now - unixEpoch).TotalSeconds);

var payload = new Dictionary<string, object>
{
    { "exp", secondsSinceEpoch }
};
var secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
var token = encoder.Encode(payload, secret);

var json = decoder.Decode(token, secret); // TokenExpiredException
```

### Custom JSON serializer

By default JSON serialization is done by JsonNetSerializer implemented using [Json.Net](https://www.json.net). To configure a different one first implement the `IJsonSerializer` interface:

```csharp
public class CustomJsonSerializer : IJsonSerializer
{
    public string Serialize(object obj)
    {
        // Implement using favorite JSON Serializer
    }

    public T Deserialize<T>(string json)
    {
        // Implement using favorite JSON Serializer
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
