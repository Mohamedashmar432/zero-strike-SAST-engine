# Deployment notes

Documentation placeholders must not be reported as leaked credentials. Every
value below is a `<...>` placeholder describing the secret rather than being
one. This case exists because a deployment guide and two triage documents were
reported as secret findings on a real scan.

    docker run \
      -e SEED_ADMIN_PASSWORD='<a real password>' \
      -e JWT_SECRET="<a 32+ character random string>" \
      app:latest

The development sentinel is written the same way:

    INSECURE_JWT_SECRET = "<dev sentinel value>"
    DATABASE_URL = "<postgres connection string>"
