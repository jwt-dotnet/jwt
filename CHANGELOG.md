# Unreleased

# JWT 11.0.0-beta3

- Added support ofr JSON web keys

# JWT.Extensions.AspNetCore 11.0.0-beta3

- Converted to use the event model to allow dependency injection with custom event classes.

# JWT 11.0.0-beta2, JWT.Extensions.AspNetCore 11.0.0-beta2, JWT.Extensions.DependencyInjection 3.0.0-beta2

- Replaced .NET 7 with .NET 8 whenever applicable
- Updated System.Text.Json to version 8.0.3

# JWT 11.0.0-beta1, JWT.Extensions.AspNetCore 11.0.0-beta1, JWT.Extensions.DependencyInjection 3.0.0-beta1

- Remove System.Text.Json when referring .NET 6 and higher as it's provided by the framework
- Updated Newtonsoft.Json to version to 13.0.3
- Updated System.Text.Json to version 6.0.9

# JWT 10.1.1

- Made ctor of ValidationParameters public, set default values for boolean properties to true

# JWT 10.1.0

- Unmarked HMAC SHA based algorithms as insecure and obsolete (was done in 9.0.0-beta4)

# JWT 10.0.3

- Added default ctor to JwtHeader and decorated it with `[JsonConstructor]`

# JWT 10.0.2

- Disallowed Encode(payload) with AddClaim(s)

# JWT 10.0.1

- Fixed deserializing JWT header
- Updated Newtonsoft.Json to version to 13.0.2
- Updated System.Text.Json to version 6.0.7

# JWT 10.0.0

- **Breaking:** Made System.Text.Json the default serializer on the platforms where it's available
- **Breaking:** Made verify=true by default in IJwtDecoder methods

- Made NoneAlgorithm not requiring any keys as it is not signed
- Added option to select default serializer, Newtonsoft.Json or System.Text.Json (#433)
- Renamed default IdentityFactory in Jwt.Extensions.AspNetCore, opened up for inheritance, extension (#428)
- Added Encode(T) and Encode(Type, object) to JwtBuilder (#415)
- Updated Newtonsoft.Json to version 13.0.1
- Fixed typos in exception messages