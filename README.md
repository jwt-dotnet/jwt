<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
- [Jwt.Net, a JWT (JSON Web Token) implementation for .NET](#jwtnet-a-jwt-json-web-token-implementation-for-net)
- [Sponsor](#sponsor)
- [Avaliable packages](#avaliable-packages)
- [Supported .NET versions:](#supported-net-versions)
- [Jwt.NET](#jwtnet)
  - [Creating (encoding) token](#creating-encoding-token)
    - [Or using the fluent builder API](#or-using-the-fluent-builder-api)
  - [Parsing (decoding) and verifying token](#parsing-decoding-and-verifying-token)
    - [Or using the fluent builder API](#or-using-the-fluent-builder-api-1)
    - [Or using the fluent builder API](#or-using-the-fluent-builder-api-2)
  - [Set and validate token expiration](#set-and-validate-token-expiration)
  - [Parsing (decoding) token header](#parsing-decoding-token-header)
    - [Or using the fluent builder API](#or-using-the-fluent-builder-api-3)
  - [Turning off parts of token validation](#turning-off-parts-of-token-validation)
    - [Or using the fluent builder API](#or-using-the-fluent-builder-api-4)
  - [Custom JSON serializer](#custom-json-serializer)
  - [Custom JSON serialization settings with the default JsonNetSerializer](#custom-json-serialization-settings-with-the-default-jsonnetserializer)
- [Jwt.Net ASP.NET Core](#jwtnet-aspnet-core)
  - [Register authentication handler to validate JWT](#register-authentication-handler-to-validate-jwt)
  - [Custom factories to produce Identity or AuthenticationTicket](#custom-factories-to-produce-identity-or-authenticationticket)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

[![Build status](https://abatishchev.visualstudio.com/OpenSource/_apis/build/status/Jwt.Net-CI)](https://abatishchev.visualstudio.com/OpenSource/_build/latest?definitionId=9)
[![Release status](https://abatishchev.vsrm.visualstudio.com/_apis/public/Release/badge/b7fc2610-91d5-4968-814c-97a9d76b03c4/2/2)](https://abatishchev.visualstudio.com/OpenSource/_release?_a=releases&view=mine&definitionId=2)

## Jwt.Net, a JWT (JSON Web Token) implementation for .NET

This library supports generating and decoding [JSON Web Tokens](https://tools.ietf.org/html/rfc7519).

## Sponsor

| | |
|-|-|
| [<img alt="Auth0 logo" src="https://cdn.auth0.com/blog/github-sponsorships/brand-evolution-logo-Auth0-horizontal-Indigo.png" height="91">](https://a0.to/try-auth0) | If you want to quickly implement a secure authentication to your JWT project, [create an Auth0 account](https://a0.to/try-auth0); it's Free! |

## Avaliable packages

1.  Jwt.Net

[![NuGet](https://img.shields.io/nuget/v/JWT.svg)](https://www.nuget.org/packages/JWT)
[![NuGet Pre](https://img.shields.io/nuget/vpre/JWT.svg)](https://www.nuget.org/packages/JWT)

2. Jwt.Net for Microsoft Dependency Injection container

[![NuGet](https://img.shields.io/nuget/v/JWT.Extensions.DependencyInjection.svg)](https://www.nuget.org/packages/JWT.Extensions.DependencyInjection)
[![NuGet Pre](https://img.shields.io/nuget/vpre/JWT.Extensions.DependencyInjection.svg)](https://www.nuget.org/packages/JWT.Extensions.DependencyInjection)

3. Jwt.Net for ASP.NET Core

[![NuGet](https://img.shields.io/nuget/v/JWT.Extensions.AspNetCore.svg)](https://www.nuget.org/packages/JWT.Extensions.AspNetCore)
[![NuGet Pre](https://img.shields.io/nuget/vpre/JWT.Extensions.AspNetCore.svg)](https://www.nuget.org/packages/JWT.Extensions.AspNetCore)

## Supported .NET versions:

- .NET Framework 3.5
- .NET Framework 4.0 - 4.8
- .NET Standard 1.3
- .NET Standard 2.0
- .NET 6.0

## Jwt.NET

### Creating (encoding) token

```c#
var payload = new Dictionary<string, object>
{
    { "claim1", 0 },
    { "claim2", "claim2-value" }
};

IJwtAlgorithm algorithm = new RS256Algorithm(certificate);
IJsonSerializer serializer = new JsonNetSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);

var token = encoder.Encode(payload);
Console.WriteLine(token);
```

#### Or using the fluent builder API

```c#
var token = JwtBuilder.Create()
                      .WithAlgorithm(new RS256Algorithm(certificate))
                      .AddClaim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds())
                      .AddClaim("claim1", 0)
                      .AddClaim("claim2", "claim2-value")
                      .Encode();

Console.WriteLine(token);
```
### Parsing (decoding) and verifying token

```c#
try
{
    IJsonSerializer serializer = new JsonNetSerializer();
    IDateTimeProvider provider = new UtcDateTimeProvider();
    IJwtValidator validator = new JwtValidator(serializer, provider);
    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
    IJwtAlgorithm algorithm = new RS256Algorithm(certificate);
    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
    
    var json = decoder.Decode(token);
    Console.WriteLine(json);
}
catch (TokenNotYetValidException)
{
    Console.WriteLine("Token is not valid yet");
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

#### Or using the fluent builder API

```c#
var json = JwtBuilder.Create()
                     .WithAlgorithm(new RS256Algorithm(certificate))
                     .MustVerifySignature()
                     .Decode(token);                    
Console.WriteLine(json);
```

The output would be:

>{ "claim1": 0, "claim2": "claim2-value" }

You can also deserialize the JSON payload directly to a .NET type:

```c#
var payload = decoder.DecodeToObject<IDictionary<string, object>>(token, secret);
```

#### Or using the fluent builder API

```c#
var payload = JwtBuilder.Create()
                        .WithAlgorithm(new RS256Algorithm(certificate))
                        .WithSecret(secret)
                        .MustVerifySignature()
                        .Decode<IDictionary<string, object>>(token);     
```

### Set and validate token expiration

As described in the [RFC 7519 section 4.1.4](https://tools.ietf.org/html/rfc7519#section-4.1.4):

>The `exp` claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.

If it is present in the payload and is prior to the current time the token will fail verification. The value must be specified as the number of seconds since the [Unix epoch](https://en.wikipedia.org/wiki/Unix_time), 1/1/1970 UTC.

```c#
IDateTimeProvider provider = new UtcDateTimeProvider();
var now = provider.GetNow().AddMinutes(-5); // token has expired 5 minutes ago

double secondsSinceEpoch = UnixEpoch.GetSecondsSince(now);

var payload = new Dictionary<string, object>
{
    { "exp", secondsSinceEpoch }
};
var token = encoder.Encode(payload);

decoder.Decode(token); // throws TokenExpiredException
```

Similarly, the `nbf` claim can be used to validate the token is not valid yet, as described in [RFC 7519 section 4.1.5](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5).

### Parsing (decoding) token header

```c#
IJsonSerializer serializer = new JsonNetSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtDecoder decoder = new JwtDecoder(serializer, urlEncoder);

JwtHeader header = decoder.DecodeHeader<JwtHeader>(token);

var typ = header.Type; // JWT
var alg = header.Algorithm; // RS256
var kid = header.KeyId; // CFAEAE2D650A6CA9862575DE54371EA980643849
```

#### Or using the fluent builder API

```c#
JwtHeader header = JwtBuilder.Create()
                             .DecodeHeader<JwtHeader>(token);

var typ = header.Type; // JWT
var alg = header.Algorithm; // RS256
var kid = header.KeyId; // CFAEAE2D650A6CA9862575DE54371EA980643849
```

### Turning off parts of token validation

If you'd like to validate a token but ignore certain parts of the validation (such as whether to the token has expired or not valid yet), you can pass a `ValidateParameters` object to the constructor of the `JwtValidator` class.

```c#
var validationParameters = new ValidationParameters
{
    ValidateSignature = true,
    ValidateExpirationTime = false,
    ValidateIssuedTime = false,
    TimeMargin = 100
};
IJwtValidator validator = new JwtValidator(serializer, provider, validationParameters);
IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
var json = decoder.Decode(expiredToken); // will not throw because of expired token
```

#### Or using the fluent builder API

```c#
var json = JwtBuilder.Create()
                     .WithAlgorithm(new RS256Algorirhm(certificate))
                     .WithSecret(secret)
                     .WithValidationParameters(
                         new ValidationParameters
                         {
                             ValidateSignature = true,
                             ValidateExpirationTime = false,
                             ValidateIssuedTime = false,
                             TimeMargin = 100
                         })
                     .Decode(expiredToken);
```

### Custom JSON serializer

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
IJwtAlgorithm algorithm = new RS256Algorirhm(certificate);
IJsonSerializer serializer = new CustomJsonSerializer();
IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
```

### Custom JSON serialization settings with the default JsonNetSerializer

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

## Jwt.Net ASP.NET Core

### Register authentication handler to validate JWT

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
                     // secrets, required only for symmetric algorithms, such as HMACSHA256Algorithm
                     // options.Keys = new[] { "mySecret" };
                     
                     // optionally; disable throwing an exception if JWT signature is invalid
                     // options.VerifySignature = false;
                 });
  // the non-generic version AddJwt() requires registering an instance of IAlgorithmFactory manually
  services.AddSingleton<IAlgorithmFactory>(new RSAlgorithmFactory(certificate));
  // or
  services.AddSingleton<IAlgorithmFactory>(new DelegateAlgorithmFactory(algorithm));

  // or use the generic version AddJwt<TFactory() to use a custom implementation of IAlgorithmFactory
  .AddJwt<MyCustomAlgorithmFactory(options => ...);
}

public void Configure(IApplicationBuilder app)
{
    app.UseAuthentication();
}
```

### Custom factories to produce Identity or AuthenticationTicket

```c#
services.AddSingleton<IIdentityFactory, CustomIdentityFctory>();
services.AddSingleton<ITicketFactory, CustomTicketFactory>();
```

## License

The following projects and their resulting packages are licensed under Public Domain, see the [LICENSE#Public-Domain](LICENSE.md#Public-Domain) file.

- JWT 

The following projects and their resulting packages are licensed under the MIT License, see the [LICENSE#MIT](LICENSE.md#MIT) file.

- JWT.Extensions.AspNetCore
- JWT.Extensions.DependencyInjection
