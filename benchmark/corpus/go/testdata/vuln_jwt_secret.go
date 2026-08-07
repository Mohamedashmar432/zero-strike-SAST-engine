package testdata

func jwtSecretHolder() {
	// ZS-GO-044: short hardcoded JWT signing key.
	// Named jwtSigningKey (not jwtSecret) so this fixture triggers only
	// ZS-GO-044 — "jwtSecret" also matches ZS-GO-005's broader
	// "secret"-in-name pattern, which would double-fire here (same
	// precedent as ZS-JAVA-008's fixture).
	jwtSigningKey := "abc123"
	_ = jwtSigningKey
}
