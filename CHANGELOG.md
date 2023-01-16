# Unreleased

- TBD

# 10.0.0

- Made NoneAlgorithm not requiring any keys as it is not signed
- Added option to select default serializer, Newtonsoft.Json or System.Text.Json (#433)
- Renamed default IdentityFactory in Jwt.Extensions.AspNetCore, opened up for inheritance, extension (#428)
- Added Encode(T) and Encode(Type, object) to JwtBuilder (#415)
- Bumped Newtonsoft.Json from 10.0.3 to 13.0.1
- Fixed typos in exception messages
- Made verify=true by default in IJwtDecoder methods
