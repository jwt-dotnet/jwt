# Unreleased

- TBD

# 10.0.2

- Disallowed Encode(payload) with AddClaim(s)

# 10.0.1

- Fixed deserializing JWT header
- Updated Newtonsoft.Json to version to 13.0.2
- Updated System.Text.Json to version 6.0.7

# 10.0.0

- Made NoneAlgorithm not requiring any keys as it is not signed
- Added option to select default serializer, Newtonsoft.Json or System.Text.Json (#433)
- Renamed default IdentityFactory in Jwt.Extensions.AspNetCore, opened up for inheritance, extension (#428)
- Added Encode(T) and Encode(Type, object) to JwtBuilder (#415)
- Updated Newtonsoft.Json to version 13.0.1
- Fixed typos in exception messages
- Made verify=true by default in IJwtDecoder methods
