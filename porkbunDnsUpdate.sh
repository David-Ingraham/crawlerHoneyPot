curl -s -X POST \
  "https://api.porkbun.com/api/json/v3/domain/updateNs/bot-traffic-analysis.io" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg secret "$PORKBUN_SECRET_API_KEY" \
    --arg key "$PORKBUN_API_KEY" \
    '{
      secretapikey: $secret,
      apikey: $key,
      ns: [
        "curitiba.ns.porkbun.com",
        "fortaleza.ns.porkbun.com",
        "maceio.ns.porkbun.com",
        "salvador.ns.porkbun.com"
      ]
    }'
  )"
