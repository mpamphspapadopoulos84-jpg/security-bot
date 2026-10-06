# Sentinel: Discord protection bot

## Setup
1. Create an app at https://discord.com/developers/applications, add a Bot, copy the token.
2. In **Bot** settings enable **Server Members Intent** and **Message Content Intent**.
3. Invite with scopes `bot` + `applications.commands` and permissions:
   Manage Roles, Manage Channels, Kick Members, Ban Members, Moderate Members,
   Manage Messages, View Audit Log, Send Messages, Embed Links.
4. **Drag Sentinel's role to the top of the role list.** Without this it cannot act on
   higher-ranked offenders (important for anti-nuke).
5. Install and run:
   ```
   pip install -r requirements.txt
   DISCORD_TOKEN=your_token python bot.py        # Windows: set DISCORD_TOKEN=your_token
   ```
6. In your server run `/security logchannel #mod-logs`, then `/security status`.

## Commands
| Command | Who | What |
|---|---|---|
| `/security status` | Admin | View all settings |
| `/security logchannel` | Admin | Where alerts are posted |
| `/security set` | Admin | Tune thresholds (spam, raid, nuke, ...) |
| `/security nukeaction` | Admin | Strip roles (default) or ban nukers |
| `/security raidmode` | Admin | Manually toggle raid mode |
| `/security whitelist` | Admin | Exempt trusted users/bots |
| `/lockdown` / `/unlock` | Admin | Lock/restore all text channels |
| `/warn`, `/warnings`, `/clearwarnings` | Mods | Manual warnings |
| `/purge` | Mods | Bulk delete messages |

Admins, the server owner and whitelisted users are exempt from automatic checks.
Warnings escalate: 2 = 10m timeout, 3 = 1h, 4-5 = 24h, 6+ = kick.

## Hosting
Needs to run 24/7: a small VPS, Railway, Fly.io or a Raspberry Pi all work.
Data is stored in `sentinel_data.json` next to the bot.
