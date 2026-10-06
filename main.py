"""
Sentinel - Discord server protection bot
----------------------------------------
Features
  * Anti-spam      : message flood + duplicate detection, auto delete + escalating punishment
  * Anti-invite    : blocks Discord invite links from non-exempt users
  * Mass mentions  : blocks @everyone / mention floods
  * Anti-raid      : detects join floods, auto raid-mode (kicks new joins), new-account filter
  * Anti-nuke      : detects mass channel/role deletion and mass bans/kicks, strips the offender
  * Warnings       : persistent, with automatic escalation (timeout -> longer timeout -> kick)
  * Lockdown       : one command locks every text channel, one command restores them
  * Logging        : every action is posted to a log channel

Run:  DISCORD_TOKEN=xxxx python bot.py
"""

import asyncio
import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sentinel")

DATA_FILE = Path(os.getenv("SENTINEL_DATA", "sentinel_data.json"))

DEFAULTS = {
    "log_channel": None,
    "whitelist": [],            # user IDs exempt from all checks
    "spam_msgs": 6,             # messages ...
    "spam_seconds": 5,          # ... within this many seconds = spam
    "dup_msgs": 3,              # identical messages within 15s = spam
    "mention_limit": 5,         # max user/role mentions per message
    "block_invites": 1,         # 1 = delete invite links
    "raid_joins": 8,            # joins ...
    "raid_seconds": 10,         # ... within this many seconds = raid
    "raid_minutes": 10,         # how long raid mode lasts
    "min_account_age_days": 3,  # kick accounts younger than this while raid mode is on
    "nuke_limit": 3,            # destructive actions ...
    "nuke_seconds": 15,         # ... within this many seconds = nuke attempt
    "nuke_action": "strip",     # "strip" (remove roles) or "ban"
    "raid_until": 0,
    "lockdown": {},             # channel_id -> previous send_messages overwrite
    "warnings": {},             # user_id -> [{"reason":..., "time":...}]
}

SETTING_KEYS = [
    "spam_msgs", "spam_seconds", "dup_msgs", "mention_limit", "block_invites",
    "raid_joins", "raid_seconds", "raid_minutes", "min_account_age_days",
    "nuke_limit", "nuke_seconds",
]

INVITE_RE = re.compile(r"(discord\.gg|discord(?:app)?\.com/invite|dsc\.gg)/[A-Za-z0-9-]+", re.I)

# ---------------------------------------------------------------- storage

class Store:
    def __init__(self, path: Path):
        self.path = path
        self.data = {}
        if path.exists():
            try:
                self.data = json.loads(path.read_text())
            except Exception:
                log.exception("Could not read data file, starting fresh")

    def cfg(self, guild_id: int) -> dict:
        g = self.data.setdefault(str(guild_id), {})
        for k, v in DEFAULTS.items():
            if k not in g:
                g[k] = json.loads(json.dumps(v))
        return g

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=2))
        tmp.replace(self.path)

store = Store(DATA_FILE)

# ---------------------------------------------------------------- bot

intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.moderation = True

bot = commands.Bot(command_prefix=commands.when_mentioned, intents=intents)

msg_log = defaultdict(lambda: deque(maxlen=30))   # (guild,user) -> deque[(ts, Message)]
join_log = defaultdict(lambda: deque(maxlen=100)) # guild -> deque[ts]
nuke_log = defaultdict(lambda: deque(maxlen=50))  # (guild,user) -> deque[ts]

NUKE_ACTIONS = {
    discord.AuditLogAction.channel_delete,
    discord.AuditLogAction.role_delete,
    discord.AuditLogAction.ban,
    discord.AuditLogAction.kick,
    discord.AuditLogAction.webhook_create,
}

# ---------------------------------------------------------------- helpers

def is_exempt(member: discord.abc.User, guild: discord.Guild) -> bool:
    if member.id == guild.owner_id or member.id == bot.user.id:
        return True
    if member.id in store.cfg(guild.id)["whitelist"]:
        return True
    if isinstance(member, discord.Member) and member.guild_permissions.administrator:
        return True
    return False

async def send_log(guild: discord.Guild, title: str, desc: str, color=discord.Color.orange()):
    cid = store.cfg(guild.id)["log_channel"]
    if not cid:
        return
    ch = guild.get_channel(cid)
    if ch:
        try:
            await ch.send(embed=discord.Embed(title=title, description=desc, color=color,
                                              timestamp=discord.utils.utcnow()))
        except discord.HTTPException:
            pass

def raid_mode_on(guild_id: int) -> bool:
    return store.cfg(guild_id)["raid_until"] > time.time()

async def add_warning(member: discord.Member, reason: str) -> int:
    cfg = store.cfg(member.guild.id)
    w = cfg["warnings"].setdefault(str(member.id), [])
    w.append({"reason": reason, "time": int(time.time())})
    store.save()
    return len(w)

async def punish(member: discord.Member, reason: str):
    """Warn and escalate: 1 = notice, 2 = 10m timeout, 3 = 1h, 4 = 24h, 6+ = kick."""
    count = await add_warning(member, reason)
    action = "Message removed + warning"
    try:
        if count == 2:
            await member.timeout(timedelta(minutes=10), reason=reason); action = "Timeout 10m"
        elif count == 3:
            await member.timeout(timedelta(hours=1), reason=reason); action = "Timeout 1h"
        elif 4 <= count <= 5:
            await member.timeout(timedelta(hours=24), reason=reason); action = "Timeout 24h"
        elif count >= 6:
            await member.kick(reason=f"Sentinel: {count} warnings"); action = "Kicked"
    except discord.Forbidden:
        action += " (could not punish: role hierarchy/permissions)"
    await send_log(member.guild, "Auto-moderation",
                   f"**User:** {member.mention} (`{member.id}`)\n**Reason:** {reason}\n"
                   f"**Warnings:** {count}\n**Action:** {action}")

# ---------------------------------------------------------------- message protection

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return
    member = message.author
    if not isinstance(member, discord.Member) or is_exempt(member, message.guild):
        return
    cfg = store.cfg(message.guild.id)
    now = time.time()
    reason = None

    if cfg["block_invites"] and INVITE_RE.search(message.content):
        reason = "Posting invite links"

    elif (len(message.mentions) + len(message.role_mentions) > cfg["mention_limit"]
          or (message.mention_everyone and not member.guild_permissions.mention_everyone)):
        reason = "Mass mentions"

    else:
        hist = msg_log[(message.guild.id, member.id)]
        hist.append((now, message))
        recent = [m for t, m in hist if now - t <= cfg["spam_seconds"]]
        dupes = [m for t, m in hist if now - t <= 15 and m.content and m.content == message.content]
        if len(recent) >= cfg["spam_msgs"]:
            reason = "Message spam"
            await purge_messages(recent)
        elif len(dupes) >= cfg["dup_msgs"]:
            reason = "Duplicate message spam"
            await purge_messages(dupes)

    if reason:
        await purge_messages([message])
        hist = msg_log[(message.guild.id, member.id)]
        hist.clear()
        await punish(member, reason)

async def purge_messages(messages):
    for m in messages:
        try:
            await m.delete()
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

# ---------------------------------------------------------------- anti-raid

@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    if member.bot:
        return
    cfg = store.cfg(guild.id)
    now = time.time()

    joins = join_log[guild.id]
    joins.append(now)
    burst = [t for t in joins if now - t <= cfg["raid_seconds"]]
    if len(burst) >= cfg["raid_joins"] and not raid_mode_on(guild.id):
        cfg["raid_until"] = now + cfg["raid_minutes"] * 60
        store.save()
        await send_log(guild, "RAID MODE ACTIVATED",
                       f"{len(burst)} joins in {cfg['raid_seconds']}s. New members will be "
                       f"removed for {cfg['raid_minutes']} minutes. Use `/security raidmode off` to end early.",
                       discord.Color.red())

    if raid_mode_on(guild.id):
        age_days = (discord.utils.utcnow() - member.created_at).days
        if age_days < cfg["min_account_age_days"] or len(burst) >= cfg["raid_joins"]:
            try:
                await member.kick(reason="Sentinel: raid mode")
                await send_log(guild, "Raid join removed",
                               f"{member} (`{member.id}`), account age {age_days}d", discord.Color.red())
            except discord.Forbidden:
                pass

# ---------------------------------------------------------------- anti-nuke

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    if entry.action not in NUKE_ACTIONS or entry.user is None:
        return
    guild = entry.guild
    actor = entry.user
    if is_exempt(actor, guild):
        return

    cfg = store.cfg(guild.id)
    now = time.time()
    hist = nuke_log[(guild.id, actor.id)]
    hist.append(now)
    burst = [t for t in hist if now - t <= cfg["nuke_seconds"]]
    if len(burst) < cfg["nuke_limit"]:
        return

    hist.clear()
    member = guild.get_member(actor.id)
    result = "No action possible"
    try:
        if cfg["nuke_action"] == "ban":
            await guild.ban(actor, reason="Sentinel: anti-nuke", delete_message_days=0)
            result = "Banned"
        elif member:
            keep = [r for r in member.roles
                    if r.is_default() or r.managed or not _dangerous(r)]
            await member.edit(roles=keep, reason="Sentinel: anti-nuke")
            result = "Dangerous roles removed"
    except discord.Forbidden:
        result = "FAILED (bot role is below the offender's role: move Sentinel's role to the top)"
    await send_log(guild, "ANTI-NUKE TRIGGERED",
                   f"**Offender:** {actor.mention} (`{actor.id}`)\n"
                   f"**Last action:** `{entry.action.name}`\n"
                   f"**Actions in {cfg['nuke_seconds']}s:** {len(burst)}\n**Result:** {result}",
                   discord.Color.red())

def _dangerous(role: discord.Role) -> bool:
    p = role.permissions
    return any([p.administrator, p.manage_guild, p.manage_roles, p.manage_channels,
                p.ban_members, p.kick_members, p.manage_webhooks, p.mention_everyone])

# ---------------------------------------------------------------- slash commands

security = app_commands.Group(name="security", description="Sentinel configuration",
                              default_permissions=discord.Permissions(administrator=True),
                              guild_only=True)

@security.command(name="status", description="Show current protection settings")
async def status(i: discord.Interaction):
    c = store.cfg(i.guild_id)
    log_ch = f"<#{c['log_channel']}>" if c["log_channel"] else "not set (use /security logchannel)"
    e = discord.Embed(title="Sentinel status", color=discord.Color.blurple())
    e.add_field(name="Log channel", value=log_ch, inline=False)
    e.add_field(name="Raid mode", value="ON" if raid_mode_on(i.guild_id) else "off")
    e.add_field(name="Lockdown", value="ON" if c["lockdown"] else "off")
    e.add_field(name="Whitelisted", value=str(len(c["whitelist"])))
    e.add_field(name="Settings", value="\n".join(f"`{k}` = {c[k]}" for k in SETTING_KEYS), inline=False)
    e.add_field(name="Anti-nuke action", value=c["nuke_action"])
    await i.response.send_message(embed=e, ephemeral=True)

@security.command(name="logchannel", description="Set the channel for security logs")
async def logchannel(i: discord.Interaction, channel: discord.TextChannel):
    store.cfg(i.guild_id)["log_channel"] = channel.id
    store.save()
    await i.response.send_message(f"Logging to {channel.mention}", ephemeral=True)

@security.command(name="set", description="Change a numeric setting")
@app_commands.choices(setting=[app_commands.Choice(name=k, value=k) for k in SETTING_KEYS])
async def set_setting(i: discord.Interaction, setting: app_commands.Choice[str],
                      value: app_commands.Range[int, 0, 1000]):
    store.cfg(i.guild_id)[setting.value] = value
    store.save()
    await i.response.send_message(f"`{setting.value}` set to `{value}`", ephemeral=True)

@security.command(name="nukeaction", description="What to do to someone who nukes the server")
@app_commands.choices(action=[app_commands.Choice(name="Strip dangerous roles", value="strip"),
                              app_commands.Choice(name="Ban", value="ban")])
async def nukeaction(i: discord.Interaction, action: app_commands.Choice[str]):
    store.cfg(i.guild_id)["nuke_action"] = action.value
    store.save()
    await i.response.send_message(f"Anti-nuke action: **{action.name}**", ephemeral=True)

@security.command(name="raidmode", description="Manually turn raid mode on or off")
@app_commands.choices(state=[app_commands.Choice(name="on", value="on"),
                             app_commands.Choice(name="off", value="off")])
async def raidmode(i: discord.Interaction, state: app_commands.Choice[str]):
    c = store.cfg(i.guild_id)
    c["raid_until"] = time.time() + c["raid_minutes"] * 60 if state.value == "on" else 0
    store.save()
    await i.response.send_message(f"Raid mode **{state.value}**", ephemeral=True)
    await send_log(i.guild, "Raid mode", f"Set **{state.value}** by {i.user.mention}")

@security.command(name="whitelist", description="Exempt or un-exempt a user from checks")
@app_commands.choices(mode=[app_commands.Choice(name="add", value="add"),
                            app_commands.Choice(name="remove", value="remove")])
async def whitelist(i: discord.Interaction, mode: app_commands.Choice[str], user: discord.User):
    wl = store.cfg(i.guild_id)["whitelist"]
    if mode.value == "add" and user.id not in wl:
        wl.append(user.id)
    elif mode.value == "remove" and user.id in wl:
        wl.remove(user.id)
    store.save()
    await i.response.send_message(f"{user.mention} {mode.value}ed.", ephemeral=True)

bot.tree.add_command(security)

@bot.tree.command(name="lockdown", description="Lock every text channel for @everyone")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def lockdown(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    c = store.cfg(i.guild_id)
    if c["lockdown"]:
        return await i.followup.send("Already in lockdown. Use /unlock.")
    everyone = i.guild.default_role
    for ch in i.guild.text_channels:
        ow = ch.overwrites_for(everyone)
        c["lockdown"][str(ch.id)] = ow.send_messages
        ow.send_messages = False
        try:
            await ch.set_permissions(everyone, overwrite=ow, reason="Sentinel lockdown")
        except discord.HTTPException:
            pass
    store.save()
    await i.followup.send("Server locked down.")
    await send_log(i.guild, "LOCKDOWN", f"Started by {i.user.mention}", discord.Color.red())

@bot.tree.command(name="unlock", description="End lockdown and restore channel permissions")
@app_commands.default_permissions(administrator=True)
@app_commands.guild_only()
async def unlock(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    c = store.cfg(i.guild_id)
    everyone = i.guild.default_role
    for cid, prev in c["lockdown"].items():
        ch = i.guild.get_channel(int(cid))
        if not ch:
            continue
        ow = ch.overwrites_for(everyone)
        ow.send_messages = prev
        try:
            await ch.set_permissions(everyone, overwrite=None if ow.is_empty() else ow,
                                     reason="Sentinel unlock")
        except discord.HTTPException:
            pass
    c["lockdown"] = {}
    store.save()
    await i.followup.send("Lockdown ended.")
    await send_log(i.guild, "Lockdown ended", f"By {i.user.mention}", discord.Color.green())

@bot.tree.command(name="warn", description="Warn a member (applies escalation)")
@app_commands.default_permissions(moderate_members=True)
@app_commands.guild_only()
async def warn(i: discord.Interaction, member: discord.Member, reason: str):
    if is_exempt(member, i.guild) or member.top_role >= i.user.top_role:
        return await i.response.send_message("You can't warn that member.", ephemeral=True)
    await i.response.send_message(f"Warned {member.mention}.", ephemeral=True)
    await punish(member, f"{reason} (by {i.user})")

@bot.tree.command(name="warnings", description="View a member's warnings")
@app_commands.default_permissions(moderate_members=True)
@app_commands.guild_only()
async def warnings(i: discord.Interaction, member: discord.Member):
    w = store.cfg(i.guild_id)["warnings"].get(str(member.id), [])
    if not w:
        return await i.response.send_message("No warnings.", ephemeral=True)
    lines = [f"{n}. <t:{x['time']}:d> {x['reason']}" for n, x in enumerate(w[-15:], 1)]
    await i.response.send_message("\n".join(lines), ephemeral=True)

@bot.tree.command(name="clearwarnings", description="Clear a member's warnings")
@app_commands.default_permissions(moderate_members=True)
@app_commands.guild_only()
async def clearwarnings(i: discord.Interaction, member: discord.Member):
    store.cfg(i.guild_id)["warnings"].pop(str(member.id), None)
    store.save()
    await i.response.send_message("Warnings cleared.", ephemeral=True)

@bot.tree.command(name="purge", description="Delete the last N messages in this channel")
@app_commands.default_permissions(manage_messages=True)
@app_commands.guild_only()
async def purge(i: discord.Interaction, amount: app_commands.Range[int, 1, 100]):
    await i.response.defer(ephemeral=True)
    deleted = await i.channel.purge(limit=amount)
    await i.followup.send(f"Deleted {len(deleted)} messages.")

# ---------------------------------------------------------------- lifecycle

@bot.event
async def setup_hook():
    await bot.tree.sync()

@bot.event
async def on_ready():
    log.info("Sentinel online as %s in %d servers", bot.user, len(bot.guilds))
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching,
                                                        name="over the server"))

if __name__ == "__main__":
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        raise SystemExit("Set the DISCORD_TOKEN environment variable first.")
    bot.run(token)
