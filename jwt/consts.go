package jwt

const (
	constHeaderTypeJwt = "JWT"

	HeaderTypeKey        = "typ"
	HeaderAlgorithmKey   = "alg"
	HeaderContentTypeKey = "cty"

	ClaimsUssuerKey   = "iss"
	ClaimsSubjectKey  = "sub"
	ClaimsAudienceKey = "aud"
	CLaimsJwtId       = "jti"

	ClaimsIssuedAtKey  = "iat"
	ClaimsExpiredAtKey = "exp"
	ClaimsNotBeforeKey = "nbf"
)
