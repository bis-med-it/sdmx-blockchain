#!/usr/bin/env sh
# Wait for Keycloak to be ready before starting the backend service

KC_URL="${KEYCLOAK_URL}"
REALM="${KEYCLOAK_REALM}"

# Remove trailing slash from KC_URL if present
KC_URL="${KC_URL%/}"

URL="$KC_URL/realms/$REALM/.well-known/openid-configuration"

echo "Waiting for Keycloak at $URL ..."
echo "KEYCLOAK_URL: $KEYCLOAK_URL"
echo "KEYCLOAK_REALM: $KEYCLOAK_REALM"

# Wait for Keycloak to be ready
for i in $(seq 1 60); do
  if curl -sf "$URL" >/dev/null 2>&1; then
    echo "Keycloak is ready."
    exit 0
  fi
  echo "Waiting ($i/60)..."
  sleep 2
done

echo "Timed out waiting for Keycloak at $URL"
echo "This may be expected on first start - Keycloak takes time to initialize"
echo "Attempting to start backend anyway..."
exit 0