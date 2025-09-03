# bot.py
import csv
import re
import sys
from io import StringIO

import discord
from discord import option
from datetime import datetime
import psutil
import dotenv
import pandas as pd
import os
import requests
from discord.ui import channel_select

dotenv.load_dotenv()
bot = discord.Bot()

async def check_mal_url(message):

    # The URL of your GitHub-hosted txt file
    url = "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/links.txt"

    # Fetch the file from GitHub
    response = requests.get(url)
    if response.status_code == 200:
        # Get the text content
        txt_data = response.text

        # Split into lines
        lines = txt_data.split("\n")

        # Check if the string exists in any line
        if any(message.content in line for line in lines):
            await message.reply("⚠️ Message was flagged for containing a malicious link.")
            await message.delete()
            settings_df = pd.read_csv("settings.csv")
            user_row = settings_df[settings_df["guild"] == message.guild.id]
            if not user_row.empty:
                channel_id = user_row.iloc[0]["mod_channel"]

                embed = discord.Embed(title="Malicious Link Detected", color=discord.Color(0xeeba2b))
                embed.add_field(name="Reported Message: ", value=str(message.content), inline=False)
                embed.add_field(name="User Reported: ", value=str(message.author), inline=False)

                try:
                    await bot.get_channel(int(channel_id)).send(embed=embed)
                except 503:
                    await message.reply(
                        "503 Forbidden. Amber doesn't have permission to send messages in the mod channel. Please ask the server admins to enable that permission.")
    else:
        print("Failed to fetch the file:", response.status_code)


async def check_mal_url_ending(message):

    # The URL of your GitHub-hosted txt file
    url = "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/trailing-slashes.txt"

    # Fetch the file from GitHub
    response = requests.get(url)
    if response.status_code == 200:
        # Get the text content
        txt_data = response.text

        # Split into lines
        lines = txt_data.split("\n")

        # Check if the string exists in any line
        if any(message.content in line for line in lines):
            await message.reply("⚠️ Message was flagged for containing a malicious link ending. Be careful when visiting this site.")

    else:
        print("Failed to fetch the file:", response.status_code)


async def check_mal_term(message):
    # The URL of your GitHub-hosted txt file
    url = "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/malicious-terms.txt"

    # Fetch the file from GitHub
    response = requests.get(url)
    if response.status_code == 200:
        # Get the text content
        txt_data = response.text

        # Split into lines
        lines = txt_data.split("\n")

        # Check if the string exists in any line
        if any(message.content in line for line in lines):
            await message.reply(
                f"⚠️ Message was flagged for containing a malicious term. Be careful when communicating with {message.author}")

    else:
        print("Failed to fetch the file:", response.status_code)


# Step 1: Download the URLhaus CSV
url = "https://urlhaus.abuse.ch/downloads/csv_online/"
response = requests.get(url)
response.raise_for_status()

csv_data = StringIO(response.text)
malicious_urls = set()

for row in csv.reader(csv_data):
    if row and not row[0].startswith("#"):
        malicious_urls.add(row[1])

# Step 2: Function to extract URLs from text
url_regex = re.compile(
    r'(https?://[^\s]+)'
)

def extract_urls(text):
    return url_regex.findall(text)

# Step 3: Check if any URL in the message is malicious
def message_contains_malicious_url(message):
    urls_in_message = extract_urls(message)
    for url in urls_in_message:
        if url in malicious_urls:
            return True, url
    return False, None


# Step 1: Download TXT files from URLs
def load_txt_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    # Strip whitespace and skip empty lines
    return set(line.strip() for line in response.text.splitlines() if line.strip())






class ReportButton(discord.ui.View):
    def __init__(self, reporter, reportee, reason, content):
        super().__init__()
        # Store values for later use
        self.reporter = reporter
        self.reportee = reportee
        self.reason = reason
        self.content = content

    @discord.ui.button(label="Submit to database.", style=discord.ButtonStyle.primary, custom_id="my_button")
    async def button_callback(self, button: discord.ui.Button, interaction: discord.Interaction):
        button.disabled = True
        await interaction.response.edit_message(view=self)
        data = {
            "reporter": self.reporter,
            "reportee": self.reportee,
            "reason": self.reason,
            "content": self.content
        }

        file_path = "reports.csv"

        new_row = pd.DataFrame(data, index=[0])
        if os.path.exists(file_path):
            new_row.to_csv(file_path, mode='a', header=False, index=False)
        else:
            # If file doesn't exist, create it with header
            new_row.to_csv(file_path, index=False)

        await interaction.followup.send(
            "Reported to Amber's database. Thank you for helping Discord a better place for everyone.", ephemeral=True)


@bot.event
async def on_ready():
    print(f"{bot.user} is ready and online!")

@bot.event
async def on_guild_join(ctx):
    guild = await bot.fetch_guild(ctx.id)
    embed = discord.Embed(title=f"Thank you for adding Amber to {guild.name}", color=discord.Color(0xeeba2b))
    embed.add_field(name="Setup", value="Let's start the setup process! To start the setup, do /setup. You can also use this to edit settings.", inline=False)
    target_channel = None
    for channel in ctx.text_channels:
        if channel.permissions_for(ctx.me).send_messages:
            target_channel = channel
            break

    if target_channel is not None:
        await target_channel.send(embed=embed)
    else:
        print("No channel to send the message to!")

@bot.event
async def on_message(message: discord.Message):
    # Ignore the bot's own messages
    if message.author == bot.user:
        return

    await check_mal_url(message)
    await check_mal_url_ending(message)
    await check_mal_term(message)


    if message_contains_malicious_url(str(message)) == True:
        await message.reply("⚠️ Message was flagged for containing a malicious link.")
        await message.delete()
        settings_df = pd.read_csv("settings.csv")
        user_row = settings_df[settings_df["guild"] == message.guild.id]
        if not user_row.empty:
            channel_id = user_row.iloc[0]["mod_channel"]

            embed = discord.Embed(title="Malicious Link Detected", color=discord.Color(0xeeba2b))
            embed.add_field(name="Reported Message: ", value=str(message.content), inline=False)
            embed.add_field(name="User Reported: ", value=str(message.author), inline=False)

            try:
                await bot.get_channel(int(channel_id)).send(embed=embed)
            except 503:
                await message.reply(
                    "503 Forbidden. Amber doesn't have permission to send messages in the mod channel. Please ask the server admins to enable that permission.")

    # Check if it's a reply
    if message.reference is not None:
        # Check if the bot was mentioned
        if bot.user in message.mentions:
            # Fetch the original replied-to message
            replied_message = await message.channel.fetch_message(message.reference.message_id)

            if replied_message.author == bot.user:
                return

            # Do your action here
            settings_df = pd.read_csv("settings.csv")
            user_row = settings_df[settings_df["guild"] == message.guild.id]
            if not user_row.empty:
                channel_id = user_row.iloc[0]["mod_channel"]

                embed = discord.Embed(title="User Report", color=discord.Color(0xeeba2b))
                embed.add_field(name="Reported By: ", value=str(message.author), inline=False)
                embed.add_field(name="Reported Message: ", value=str(replied_message.content), inline=False)
                embed.add_field(name="User Reported: ", value=str(replied_message.author), inline=False)
                embed.add_field(name="Reason: ", value=str(message.content), inline=False)


                view = ReportButton(message.author.id, replied_message.author.id, message.content, replied_message.content)
                try:
                    await bot.get_channel(int(channel_id)).send(embed=embed, view=view)
                    await message.reply("Message Successfully Reported!")
                except 503:
                    await message.reply("503 Forbidden. Amber doesn't have permission to send messages in the mod channel. Please ask the server admins to enable that permission.")

@bot.command(name="debug", description="Sends a debug report")
async def debug(ctx):
    """Send an ephemeral debug message with system info."""
    # Get latency
    latency = round(ctx.bot.latency * 1000)

    # Get CPU and memory usage
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_info = psutil.virtual_memory()
    memory_used = round(memory_info.used / (1024 * 1024), 1)
    memory_total = round(memory_info.total / (1024 * 1024 * 1024), 1)

    # Embed creation
    embed = discord.Embed(title="Debug", color=discord.Color(0xeeba2b))
    embed.add_field(name="<:peep:1408020069400969236> Peep Says:", value=" ", inline=False)
    embed.add_field(name="Ping", value=f"{latency}ms", inline=False)
    embed.add_field(name="Integration Type", value="User", inline=False)
    embed.add_field(name="Context", value="Guild", inline=False)
    embed.add_field(name="Shard ID", value=f"{ctx.guild.shard_id}", inline=False)
    embed.add_field(name="Guild ID", value=f"{ctx.guild.id}", inline=False)
    embed.add_field(name="Channel ID", value=f"{ctx.channel.id}", inline=False)
    embed.add_field(name="Author ID", value=f"{ctx.author.id}", inline=False)
    embed.add_field(name="CPU", value=f"{cpu_percent}%", inline=False)
    embed.add_field(name="Memory", value=f"{memory_used} MB Used / {memory_total} GB", inline=False)

    # Add a footer with the current date and time
    embed.set_footer(text=f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    await ctx.respond(embed=embed, ephemeral=True)

@bot.command(name="setup", description="Sets up / edits the server settings")
@option("mod channel", discord.TextChannel, description="Your Mod Channel")
@option("mod role", discord.Role, description="Pick a mod role")
async def setup(ctx: discord.ApplicationContext, channel: discord.TextChannel, role: discord.Role, opt: bool):
    df = pd.read_csv("settings.csv")
    if ctx.guild.id not in df["guild"].values:
        data = {
            "guild": ctx.guild.id,
            "mod_channel": channel.id,
            "mod_role": role.id
        }

        file_path = "settings.csv"

        new_row = pd.DataFrame(data, index=[0])
        if os.path.exists(file_path):
            new_row.to_csv(file_path, mode='a', header=False, index=False)
        else:
            # If file doesn't exist, create it with header
            new_row.to_csv(file_path, index=False)
        await ctx.respond("Amber set up! Enjoy a streamlined reporting workflow and spam filters!")
    elif ctx.guild.id in df["guild"].values:
        df.loc[df["guild"] == ctx.guild.id, "mod_channel"] == channel.id
        df.loc[df["guild"] == ctx.guild.id, "mod_role"] == channel.id
        df.to_csv("settings.csv", index=False)



try:
    bot.run(dotenv.get_key(key_to_get='DISCORD_TOKEN', dotenv_path='.env'))
except bot.exceptions.DiscordException:
    print("Discord token not found.")
except KeyError:
    print("Discord token not found.")
except bot.exceptions.HTTPException:
    print("Network error.")
except Exception:
    print("Unexpected error:", sys.exc_info()[0])
