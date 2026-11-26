# Cyber Alert Bot → WhatsApp

Every 5 minutes, GitHub Actions checks these sources and sends new items to WhatsApp through the Meta Cloud API:

- CISA KEV (zero-days exploited in the wild)
- NVD critical CVEs for our vendors
- Security news (The Hacker News, BleepingComputer, SecurityWeek)
- Vendor advisories (Microsoft, Cisco, Fortinet, Palo Alto, Oracle, CISA)
- Cloud status pages (Azure, AWS, Cloudflare, GitHub, Google Cloud, Palo Alto)

**How alerts are sent**
- **Instantly, one message each:** actively exploited zero-days, critical CVEs that match the products in config.json, and urgent outages.
- **Grouped into one digest message:** everything else.

**Duplicates:** the bot tracks what it has already sent in state/seen.json, so you never get the same item twice.

## Settings
- **Products and vendors to watch:** edit watch_vendors in config.json.
- **Feeds:** add or remove them under sources.rss in config.json. Set "urgent": true on a feed to have its items sent instantly.
- **Secrets** (Settings → Secrets and variables → Actions):
  - WHATSAPP_TO: recipient numbers, comma-separated, with country code and no +
  - META_TOKEN: Meta access token
  - META_PHONE_NUMBER_ID: Meta phone number ID
  - META_TEMPLATE_NAME: template name (default security_alert)
  - META_TEMPLATE_LANG: template language (default en)
  - NVD_API_KEY: optional
- **Re-send the "bot is live" message:** delete state/seen.json, then run the workflow again.
