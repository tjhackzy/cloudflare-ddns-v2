# cloudflare-ddns-v2

Improved version of Cloudflare DDNS. 

(forked from : timothymiller/cloudflare-ddns)

This will notify you once the record is either added/updated or deleted at cloudflare dashboard via Gotify.

Also, now you can set the custom TTL within subdomains while updating the records. 

Moreover, you can set the custom time interval within config file. Min is 1 (min).

# Demo config.json file : 

```json
{
  "cloudflare": [
    {
      "authentication": {
        "api_token": "",
        "api_key": {
          "api_key": "",
          "account_email": ""
        }
      },
      "zone_id": "",
      "subdomains": [
        "nextcloud",
        "*.subdomain"
      ],
      "proxied": false,
      "ttls": 60
    }
  ],
  "interval": 1,
  "a": true,
  "aaaa": false,
  "purgeUnknownRecords": false,
  "Gotify_BaseURL": "https://gotify.myhomelab.tld",
  "Gotify_AppToken": "aaaaaaaa-aaaaa",
  "Gotify_Notification_Title": "Cloudflare-DDNS Update"
}
```

You can remove the "Gotify_" fields from above config if you do not want to get notified.
They are optional.



# Docker-Compose :

```markdown 
version: "3.7"
services:
  cloudflare-ddns-v2:
    image: tjhackz/cloudflare-ddns-v2:arm64v8
    container_name: cloudflare-ddns-v2
    security_opt:
      - no-new-privileges:true
    network_mode: "host"
    environment:
      - PUID=1000
      - PGID=1000
    volumes:
      - /PATH/TO/HOST/config.json:/config.json
    restart: unless-stopped
```

# Docker Hub URL 
https://hub.docker.com/r/tjhackz/cloudflare-ddns-v2/tags

## Supported Tags/Architecutures :
latest, armv7, arm64v8, amd64






