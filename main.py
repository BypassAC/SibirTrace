import os
import re
import ipaddress
import asyncio
import socket
from typing import Dict, Optional, Tuple, List

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv



load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN", "")

INTENTS = discord.Intents.none()  
BOT_NAME = "SibirTrace"
THEME_COLOR = 0x00FF7F   



RU = {
    "ready": "Бот запущен. Готов к разведке.",
    "scan_title": "ТРЕССКАН: Проверка никнейма",
    "scan_desc": "Анализ публичных профилей по нику",
    "scan_field_platform": "Платформа",
    "scan_field_status": "Статус",
    "scan_found": "Найдено",
    "scan_not_found": "Нет",
    "scan_unknown": "Неизвестно",
    "gh_title": "GitHub разведка",
    "ip_title": "IP разведка",
    "whois_title": "WHOIS разведка",
    "error": "Произошла ошибка. Попробуйте позже.",
}

PLATFORMS: Dict[str, str] = {
    "GitHub": "https://github.com/{u}",
    "Twitter": "https://x.com/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Instagram": "https://www.instagram.com/{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Spotify": "https://open.spotify.com/user/{u}",
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)




def make_embed(title: str, description: str = "") -> discord.Embed:
    e = discord.Embed(title=title, description=description, color=THEME_COLOR)
    e.set_footer(text=f"{BOT_NAME} • OSINT")
    return e

async def resolve_domain_to_ip(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

async def fetch_json(session: aiohttp.ClientSession, url: str) -> Optional[dict]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                return await r.json()
    except Exception:
        pass
    return None

async def fetch_text(session: aiohttp.ClientSession, url: str) -> Tuple[int, Optional[str]]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            txt = await r.text(errors="ignore")
            return r.status, txt
    except Exception:
        return 0, None

async def head_status(session: aiohttp.ClientSession, url: str) -> int:
    try:
        async with session.head(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as r:
            return r.status
    except Exception:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as r:
                return r.status
        except Exception:
            return 0


async def whois_query(domain: str) -> str:
    domain = domain.strip().lower()

    def _query(server: str, query: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(8)
            s.connect((server, 43))
            s.sendall((query + "\r\n").encode("utf-8"))
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode("utf-8", errors="ignore")

    try:
        referral = _query("whois.iana.org", domain)
        m = re.search(r"refer:\s*(?P<srv>[^\s]+)", referral)
        whois_server = m.group("srv").strip() if m else "whois.iana.org"
    except Exception:
        whois_server = "whois.iana.org"

    try:
        result = _query(whois_server, domain)
        if not result.strip() and whois_server != "whois.iana.org":
            result = _query("whois.iana.org", domain)
        return result
    except Exception as e:
        return f"<ошибка whois: {e}>"


class SibirTrace(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix=commands.when_mentioned_or("!"), intents=INTENTS)
        self.session: Optional[aiohttp.ClientSession] = None

    async def setup_hook(self) -> None:
        try:
            await self.tree.sync()
        except Exception:
            pass

    async def on_ready(self):
        print(f"[{BOT_NAME}] {RU['ready']} Вошёл как {self.user} (id={self.user.id})")

    async def start(self, *args, **kwargs):
        headers = {"User-Agent": USER_AGENT}
        timeout = aiohttp.ClientTimeout(total=15)
        self.session = aiohttp.ClientSession(headers=headers, timeout=timeout)
        print("[ИНФО] Сессия aiohttp открыта")
        await super().start(*args, **kwargs)

    async def close(self):
        if self.session:
            await self.session.close()
            print("[ИНФО] Сессия aiohttp закрыта")
        await super().close()


bot = SibirTrace()




@bot.tree.command(name="ping", description="Latency check — Пинг")
async def ping(interaction: discord.Interaction):
    await interaction.response.send_message(f"Понг! {round(bot.latency*1000)}мс", ephemeral=True)


@bot.tree.command(name="lookup", description="Проверка никнейма по платформам")
@app_commands.describe(username="Никнейм для проверки")
async def lookup(interaction: discord.Interaction, username: str):
    await interaction.response.defer(thinking=True)
    session = bot.session
    if not session:
        return await interaction.followup.send(RU["error"], ephemeral=True)

    tasks = []
    urls: List[Tuple[str, str]] = []
    for platform, pattern in PLATFORMS.items():
        url = pattern.format(u=username)
        urls.append((platform, url))
        tasks.append(head_status(session, url))

    statuses = await asyncio.gather(*tasks)
    embed = make_embed(RU["scan_title"], f"**{username}** — {RU['scan_desc']}")

    for (platform, url), status in zip(urls, statuses):
        if status == 200:
            state = f" {RU['scan_found']}"
        elif status == 404:
            state = f" {RU['scan_not_found']}"
        elif status == 0:
            state = f" {RU['scan_unknown']} (нет ответа)"
        else:
            state = f" {RU['scan_unknown']} ({status})"
        embed.add_field(name=platform, value=f"{state}\n{url}", inline=False)

    await interaction.followup.send(embed=embed)


@bot.tree.command(name="github", description="GitHub разведка")
@app_commands.describe(user="GitHub username")
async def github_cmd(interaction: discord.Interaction, user: str):
    await interaction.response.defer(thinking=True)
    session = bot.session
    if not session:
        return await interaction.followup.send(RU["error"], ephemeral=True)

    api = f"https://api.github.com/users/{user}"
    data = await fetch_json(session, api)
    if not data or "message" in data:
        return await interaction.followup.send("Профиль не найден / rate limit.")

    name = data.get("name") or user
    bio = data.get("bio") or "—"
    followers = data.get("followers", 0)
    following = data.get("following", 0)
    repos = data.get("public_repos", 0)
    created = data.get("created_at", "?")
    html = data.get("html_url", f"https://github.com/{user}")
    avatar = data.get("avatar_url")

    e = make_embed(RU["gh_title"], f"**{name}** — {html}")
    e.add_field(name="Био", value=str(bio)[:1024] or "—", inline=False)
    e.add_field(name="Репозитории", value=str(repos))
    e.add_field(name="Подписчики/Подписки", value=f"{followers}/{following}")
    e.add_field(name="Создан", value=str(created))
    if avatar:
        e.set_thumbnail(url=avatar)
    await interaction.followup.send(embed=e)


@bot.tree.command(name="ip", description="IP/Domain разведка")
@app_commands.describe(target="IPv4/IPv6 или домен")
async def ip_cmd(interaction: discord.Interaction, target: str):
    await interaction.response.defer(thinking=True)
    session = bot.session
    if not session:
        return await interaction.followup.send(RU["error"], ephemeral=True)

    ip: Optional[str] = None
    try:
        ipaddress.ip_address(target)
        ip = target
    except ValueError:
        ip = await resolve_domain_to_ip(target)

    if not ip:
        return await interaction.followup.send("Неверный IP/домен.")

    url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,country,regionName,city,zip,lat,lon,isp,org,as,query"
    info = await fetch_json(session, url)

    if not info or info.get("status") != "success":
        return await interaction.followup.send("Не удалось получить данные по IP.")

    e = make_embed(RU["ip_title"], f"**{ip}** — результат поиска")
    e.add_field(name="Страна", value=info.get("country", "—"))
    e.add_field(name="Регион", value=info.get("regionName", "—"))
    e.add_field(name="Город", value=info.get("city", "—"))
    e.add_field(name="Провайдер", value=info.get("isp", "—"))
    e.add_field(name="ORG", value=info.get("org", "—"))
    e.add_field(name="AS", value=info.get("as", "—"))
    e.add_field(name="Координаты", value=f"{info.get('lat', '—')}, {info.get('lon', '—')}")
    await interaction.followup.send(embed=e)


@bot.tree.command(name="whois", description="WHOIS разведка")
@app_commands.describe(domain="Домен, напр. example.com")
async def whois_cmd(interaction: discord.Interaction, domain: str):
    await interaction.response.defer(thinking=True)
    if not re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", domain):
        return await interaction.followup.send("Некорректный домен.")

    text = await whois_query(domain)

    MAX = 3800
    snippet = text if len(text) <= MAX else text[:MAX] + "\n... (обрезано)"

    e = make_embed(RU["whois_title"], f"`{domain}`\n\n```\n{snippet}\n```")
    await interaction.followup.send(embed=e)



if __name__ == "__main__":
    if not TOKEN:
        print("[ОШИБКА] Токен Discord не найден. Создайте .env с DISCORD_TOKEN=...")
    else:
        try:
            print("[СТАРТ] Запускаем бота...")
            bot.run(TOKEN)
        except KeyboardInterrupt:
            print("\n[ВЫКЛЮЧЕНИЕ] До связи, товарищ.")
