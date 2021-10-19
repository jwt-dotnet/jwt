[![Build status](https://abatishchev.visualstudio.com/OpenSource/_apis/build/status/Jwt.Net-CI)](https://abatishchev.visualstudio.com/OpenSource/_build/latest?definitionId=9)
[![Release status](https://abatishchev.vsrm.visualstudio.com/_apis/public/Release/badge/b7fc2610-91d5-4968-814c-97a9d76b03c4/2/2)](https://abatishchev.visualstudio.com/OpenSource/_release?_a=releases&view=mine&definitionId=2)

# Jwt.Net, a JWT (JSON Web Token) implementation for .NET

This library supports generating and decoding [JSON Web Tokens](https://tools.ietf.org/html/rfc7519).

# Sponsor

| | |
|-|-|
| [<img alt="Auth0 logo" src="https://cdn.auth0.com/blog/github-sponsorships/brand-evolution-logo-Auth0-horizontal-Indigo.png" height="91">](https://a0.to/try-auth0) | If you want to quickly implement a secure authentication to your JWT project, [create an Auth0 account](https://a0.to/try-auth0); it's Free! |

## Avaliable packages

1. [Jwt.Net](#JwtNet)
2. [Jwt.Net for ASP.NET Core](#JwtNet-ASPNET-Core)
3. [Jwt.Net for Owin](#JwtNet-OWIN)

## Supported .NET versions:

- .NET Framework 3.5
- .NET Framework 4.0 - 4.8
- .NET Standard 1.3
- .NET Standard 2.0
- .NET 5.0

## License

The following projects and their resulting packages are licensed under Public Domain, see the [LICENSE#Public-Domain](LICENSE.md#Public-Domain) file.

- JWT 

The following projects and their resulting packages are licensed under the MIT License, see the [LICENSE#MIT](LICENSE.md#MIT) file.

- JWT.Extensions.AspNetCore
- JWT.Extensions.Owin

### Jwt.NET

#### NuGet

[![NuGet](https://img.shields.io/nuget/v/JWT.svg)](https://www.nuget.org/packages/JWT)
[![NuGet Pre](https://img.shields.io/nuget/vpre/JWT.svg)](https://www.nuget.org/packages/JWT)

#### Creating (encoding) token

```c#
var payload = new Dictionary<string, object>
{
    { "claim1", 0 },
    { "claim2", "claim2-value" }
};
const string secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
IJsonSerializer serializer = new JsonNetSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

var token = encoder.Encode(payload, secret);
Console.WriteLine(token);
```

##### Or using the fluent builder API

```c#
var token = JwtBuilder.Create()
                      .WithAlgorithm(new HMACSHA256Algorithm()) // symmetric
                      .WithSecret(secret)
                      .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                      .AddClaim("claim2", "claim2-value")
                      .Encode();

Console.WriteLine(token);
```

The output would be:

>eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s

#### Parsing (decoding) and verifying token

```c#
const string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
const string secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";

try
{
    IJsonSerializer serializer = new JsonNetSerializer();
    IDateTimeProvider provider = new UtcDateTimeProvider();
    IJwtValidator validator = new JwtValidator(serializer, provider);
    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
    IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
    
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

##### Or using the fluent builder API

```c#
var json = JwtBuilder.Create()
                     .WithAlgorithm(new HMACSHA256Algorithm()) // symmetric
                     .WithSecret(secret)
                     .MustVerifySignature()
                     .Decode(token);                    
Console.WriteLine(json);
```

or

```c#
var json = JwtBuilder.Create()
                     .WithAlgorithm(new RS256Algorithm(certificate)) // asymmetric
                     .MustVerifySignature()
                     .Decode(token);                    
Console.WriteLine(json);
```

The output would be:

>{ "claim1": 0, "claim2": "claim2-value" }

You can also deserialize the JSON payload directly to a .NET type:

```c#
var payload = decoder.DecodeToObject<IDictionary<string, object>>(token, secret);
Console.WriteLine(payload["claim2"]);
 ```

##### Or using the fluent builder API

```c#
var payload = JwtBuilder.Create()
                        .WithAlgorithm(new HMACSHA256Algorithm()) // symmetric
                        .WithSecret(secret)
                        .MustVerifySignature()
                        .Decode<IDictionary<string, object>>(token);     
Console.WriteLine(payload["claim2"]);
```

and

```c#
var payload = JwtBuilder.Create()
                        .WithAlgorithm(new RS256Algorithm(certificate)) // asymmetric
                        .MustVerifySignature()
                        .Decode<IDictionary<string, object>>(token);     
Console.WriteLine(payload["claim2"]);
```

The output would be:
    
>claim2-value

#### Set and validate token expiration

As described in the [JWT RFC](https://tools.ietf.org/html/rfc7519#section-4.1.4):

>The `exp` claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.

If it is present in the payload and is prior to the current time the token will fail verification. The value must be specified as the number of seconds since the [Unix epoch](https://en.wikipedia.org/wiki/Unix_time), 1/1/1970 UTC.

```c#
IDateTimeProvider provider = new UtcDateTimeProvider();
var now = provider.GetNow();

double  secondsSinceEpoch = UnixEpoch.GetSecondsSince(now);

var payload = new Dictionary<string, object>
{
    { "exp", secondsSinceEpoch }
};
const string secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
var token = encoder.Encode(payload, secret);

var json = decoder.Decode(token, secret, validate: true); // throws TokenExpiredException
```

#### Parsing (decoding) token header

```c#
IJsonSerializer serializer = new JsonNetSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtDecoder decoder = new JwtDecoder(serializer, urlEncoder);

JwtHeader header = decoder.DecodeHeader<JwtHeader>(token);

var typ = header.Type; // JWT
var alg = header.Algorithm; // RS256
var kid = header.KeyId; // CFAEAE2D650A6CA9862575DE54371EA980643849
```

##### Or using the fluent builder API

```c#
JwtHeader header = JwtBuilder.Create()
                             .DecodeHeader<JwtHeader>(token);

var typ = header.Type; // JWT
var alg = header.Algorithm; // RS256
var kid = header.KeyId; // CFAEAE2D650A6CA9862575DE54371EA980643849
```

#### Custom JSON serializer

By default JSON serialization is performed by JsonNetSerializer implemented using [Json.Net](https://www.json.net). To use a different one, implement the `IJsonSerializer` interface:

```c#
public sealed class CustomJsonSerializer : IJsonSerializer
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

And then pass this serializer to JwtEncoder constructor:

```c#
IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
IJsonSerializer serializer = new CustomJsonSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
```

#### Custom JSON serialization settings with the default JsonNetSerializer

As mentioned above, the default JSON serialization is done by `JsonNetSerializer`. You can define your own custom serialization settings as follows:

```c#
JsonSerializer customJsonSerializer = new JsonSerializer
{
    // All keys start with lowercase characters instead of the exact casing of the model/property, e.g. fullName
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

### Jwt.Net ASP.NET Core

#### NuGet

[![NuGet](https://img.shields.io/nuget/v/JWT.Extensions.AspNetCore.svg)](https://www.nuget.org/packages/JWT.Extensions.AspNetCore)
[![NuGet Pre](https://img.shields.io/nuget/vpre/JWT.Extensions.AspNetCore.svg)](https://www.nuget.org/packages/JWT.Extensions.AspNetCore)

#### Register authentication handler to validate JWT

```c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options =>
                 {
                     options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;
                     options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
                 })
            .AddJwt(options =>
                 {
                     // secrets, required only for symmetric algorithms
                     options.Keys = new[] { "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk" };
                     
                     // force JwtDecoder to throw exception if JWT signature is invalid
                     options.VerifySignature = true;
                 });
  // the non-generic version AddJwt() requires you to register an instance of IAlgorithmFactory manually
  services.AddSingleton<IAlgorithmFactory>(new RSAlgorithmFactory(certificate));
  // or
  services.AddSingleton<IAlgorithmFactory>(new DelegateAlgorithmFactory(algorithm));

  // or use the generic version AddJwt<TFactory() if you have a custom implementation of IAlgorithmFactory
  // AddJwt<MyCustomAlgorithmFactory(options => ...);
}

public void Configure(IApplicationBuilder app)
{
    app.UseAuthentication();
}
```

#### Custom factories to produce Identity or AuthenticationTicket

```c#
options.IdentityFactory = dic => new ClaimsIdentity(
    dic.Select(p => new Claim(p.Key, p.Value)));

options.TicketFactory = (identity, scheme) => new AuthenticationTicket(
    new ClaimsPrincipal(identity),
    new AuthenticationProperties(),
    scheme.Name);
```

#### Register middleware to validate JWT

```c#
services.AddAuthentication(options =>
    {
        // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found.
        options.DefaultAuthenticateScheme = JwtAuthenticationDefaults.AuthenticationScheme;

        // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultChallengeScheme found.
        options.DefaultChallengeScheme = JwtAuthenticationDefaults.AuthenticationScheme;
    })
.AddJwt(options =>
    {
        options.Keys = configureOptions.Keys;
        options.VerifySignature = configureOptions.VerifySignature;
    });
```

### Jwt.Net OWIN

#### NuGet

[![NuGet](https://img.shields.io/nuget/v/JWT.Extensions.Owin.svg)](https://www.nuget.org/packages/JWT.Extensions.Owin)
[![NuGet Pre](https://img.shields.io/nuget/vpre/JWT.Extensions.Owin.svg)](https://www.nuget.org/packages/JWT.Extensions.Owin)

#### Register middleware to validate JWT

```c#
app.UseJwtMiddleware();
```

**Note:** work in progress as the scenario/usage is not designed yet. The registered component will do nothing but throw an exception.
