# Unreleased

# 11.0.0

- Converted the JWT.Extensions.AspNetCore to use the Event model. This will allow for DI in custom Event classes.

# 10.1.1

- Made ctor of ValidationParameters public, set default values for boolean properties to true

# 10.1.0

- Unmarked HMAC SHA based algorithms as insecure and obsolete (was done in 9.0.0-beta4)

# 10.0.3

- Added default ctor to JwtHeader and decorated it with `[JsonConstructor]`

# 10.0.2

- Disallowed Encode(payload) with AddClaim(s)

# 10.0.1

- Fixed deserializing JWT header
- Updated Newtonsoft.Json to version to 13.0.2
- Updated System.Text.Json to version 6.0.7

# 10.0.0

- **Breaking:** Made System.Text.Json the default serializer on the platforms where it's available
- **Breaking:** Made verify=true by default in IJwtDecoder methods

- Made NoneAlgorithm not requiring any keys as it is not signed
- Added option to select default serializer, Newtonsoft.Json or System.Text.Json (#433)
- Renamed default IdentityFactory in Jwt.Extensions.AspNetCore, opened up for inheritance, extension (#428)
- Added Encode(T) and Encode(Type, object) to JwtBuilder (#415)
- Updated Newtonsoft.Json to version 13.0.1
- Fixed typos in exception messages
