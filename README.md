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
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
    string token = JWT.JsonWebToken.Encode(payload, secretKey, JWT.JwtHashAlgorithm.HS256);
    Console.Out.WriteLine(token);

Output will be:

    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s

### Verifying and Decoding Tokens

    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjbGFpbTEiOjAsImNsYWltMiI6ImNsYWltMi12YWx1ZSJ9.8pwBI_HtXqI3UgQHQ_rDRnSQRxFL1SR8fbQoS-5kM5s";
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
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

#### exp claim

As described in the [JWT RFC](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.4) the `exp` "claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing." If an `exp` claim is present and is prior to the current time the token will fail verification. The exp (expiry) value must be specified as the number of seconds since 1/1/1970 UTC.

    var now = Math.Round((DateTime.UtcNow - new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds);
    var payload = new Dictionary<string, object>() {
        { "exp", now }
    };
    var secretKey = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
    string token = JWT.JsonWebToken.Encode(payload, secretKey, JWT.JwtHashAlgorithm.HS256);

    string jsonPayload = JWT.JsonWebToken.Decode(token, secretKey);
    // !! JWT.SignatureVerificationException