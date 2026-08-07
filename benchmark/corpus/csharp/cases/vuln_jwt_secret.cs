class VulnJwtSecret
{
    // ZS-CS-033: short hardcoded JWT signing key.
    // Named jwtSigningKey (not jwtSecret) so this fixture triggers only
    // ZS-CS-033 — "jwtSecret" also matches ZS-CS-006's broader
    // "secret"-in-name pattern, which would double-fire here (same
    // precedent as ZS-JAVA-008's fixture).
    string jwtSigningKey = "abc123";
}
