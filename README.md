# JSON Web Token (JWT) Implementation for .NET

This library supports generating and decoding [JSON Web Tokens](http://tools.ietf.org/html/draft-jones-json-web-token-10).

## Installation
The easiest way to install is via NuGet.  See [here](https://nuget.org/packages/JWT).  Else, you can download and compile it yourself.

## Usage
### Creating Tokens
    var payload = new Dictionary<string, object>() {
        { "claim1", 0 },
        { "claim2", "claim2-value" }
    };
    var secretKey = Convert.FromBase64String("GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk");
    string token = JWT.JsonWebToken.Encode(payload, secretKey, JWT.JwtHashAlgorithm.HS256);
    Console.Out.WriteLine(token);

Output will be:

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s

### Verifying and Decoding Tokens

    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
    var secretKey = Convert.FromBase64String("GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk");
    try
    {
        string jsonPayload = JWT.JsonWebToken.Decode(token, secretKey);
        Console.Out.WriteLine(jsonPayload);
    }
    catch (JWT.SignatureVerificationException)
    {
        Console.Out.WriteLine("Invalid token!");
    }

Output will be:

    {"claim1":0,"claim2":"claim2-value"}

You can also deserialize the JSON payload directly to a .Net object with DecodeToObject:

    var payload = JWT.JsonWebToken.DecodeToObject(token, secretKey) as IDictionary<string, object>;
    Console.Out.WriteLine(payload["claim2"]);

which will output:
    
    claim2-value

### Audience, Issuer and Expiration check

The library support checking audience (aud), issuer (iss) and expiration (exp). By default these checks are turn off for backward compatibility but if you specify them, it will do the check. If the check fails it will throw a `TokenValidationException`.

    var payload = JWT.JsonWebToken.DecodeToObject(token, secretKey, audience: "urn:myaudience", issuer: "my:issuer", checkExpiration: true) as IDictionary<string, object>;

