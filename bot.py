# bot.py
import csv
import re
import sys
from io import StringIO
from discord.ext import commands
import discord
from discord import option
from datetime import datetime
import psutil
import dotenv
import pandas as pd
import os
import requests

dotenv.load_dotenv()

# Enable necessary intents
intents = discord.Intents.default()
intents.message_content = True  # This is required to read message content

bot = discord.Bot(intents=intents)


async def check_mal_url(message):
    try:
        # The URL of your GitHub-hosted txt file
        url = "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/links.txt"

        # Fetch the file from GitHub
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Get the text content
            txt_data = response.text

            # Split into lines and clean them
            lines = [line.strip() for line in txt_data.split("\n") if line.strip()]

            # Debug: print first few lines

            # Check if any line is contained in the message (case-insensitive)
            message_lower = message.content.lower()
            for line in lines:
                if line.lower() in message_lower:

                    try:
                        await message.reply("⚠️ Message was flagged for containing a malicious link.")
                        await message.delete()
                    except (discord.NotFound, discord.HTTPException):
                        # Message was already deleted or doesn't exist
                        pass

                    # Send to mod channel
                    await send_to_mod_channel(message, "Malicious Link Detected")
                    return  # Exit after first match
        else:
            print("Failed to fetch the file:", response.status_code)
    except Exception as e:
        print(f"Error in check_mal_url: {e}")


async def check_mal_url_ending(message):
    try:
        # The URL of your GitHub-hosted txt file
        url = "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/trailing-slashes.txt"

        # Fetch the file from GitHub
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Get the text content
            txt_data = response.text

            # Split into lines and clean them
            lines = [line.strip() for line in txt_data.split("\n") if line.strip()]


            # Check if any line is contained in the message (case-insensitive)
            message_lower = message.content.lower()
            for line in lines:
                if line.lower() in message_lower:
                    print(f"TRAILING SLASH MATCH: '{line}' in '{message.content}'")
                    try:
                        await message.reply(
                            "⚠️ Message was flagged for containing a malicious link ending. Be careful when visiting this site.")
                    except (discord.NotFound, discord.HTTPException):
                        # Message was already deleted or doesn't exist
                        pass
                    return  # Exit after first match
        else:
            print("Failed to fetch the file:", response.status_code)
    except Exception as e:
        print(f"Error in check_mal_url_ending: {e}")


async def check_mal_term(message):
    try:
        # This file contains phrases like "discord is giving", "catch the nitro"
        url = "https://raw.githubusercontent.com/DevSpen/scam-links/master/src/malicious-terms.txt"

        # Fetch the file from GitHub
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Get the text content
            txt_data = response.text

            # Split into lines and clean them
            lines = [line.strip() for line in txt_data.split("\n") if line.strip()]



            # Check if any phrase is contained in the message (case-insensitive)
            message_lower = message.content.lower()
            for phrase in lines:
                if phrase.lower() in message_lower:
                    print(f"MALICIOUS PHRASE MATCH: '{phrase}' in '{message.content}'")
                    try:
                        await message.reply(
                            f"⚠️ Message was flagged for containing a malicious term. Be careful when communicating with {message.author}")
                    except (discord.NotFound, discord.HTTPException):
                        # Message was already deleted or doesn't exist
                        pass
                    return  # Exit after first match

            print("")
        else:
            print("Failed to fetch the file:", response.status_code)
    except Exception as e:
        print(f"Error in check_mal_term: {e}")


async def send_to_mod_channel(message, title):
    """Helper function to send alerts to mod channel"""
    try:
        settings_df = pd.read_csv("settings.csv")
        user_row = settings_df[settings_df["guild"] == message.guild.id]
        if not user_row.empty:
            channel_id = user_row.iloc[0]["mod_channel"]

            embed = discord.Embed(title=title, color=discord.Color(0xeeba2b))
            embed.add_field(name="Reported Message: ", value=str(message.content), inline=False)
            embed.add_field(name="User Reported: ", value=str(message.author), inline=False)

            try:
                await bot.get_channel(int(channel_id)).send(embed=embed)
            except (discord.Forbidden, discord.NotFound):
                # Can't send to mod channel - permissions or channel doesn't exist
                pass
            except discord.HTTPException as e:
                print(f"Failed to send to mod channel: {e}")
    except FileNotFoundError:
        print("settings.csv not found")
    except Exception as e:
        print(f"Error sending to mod channel: {e}")


# Load malicious URLs at startup
try:
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    response = requests.get(url, timeout=10)
    response.raise_for_status()

    csv_data = StringIO(response.text)
    malicious_urls = set()

    for row in csv.reader(csv_data):
        if row and len(row) > 1 and not row[0].startswith("#"):
            malicious_urls.add(row[1].strip())

except Exception as e:
    print(f"Failed to load malicious URLs: {e}")
    malicious_urls = set()

# Function to extract URLs from text
url_regex = re.compile(r'(https?://[^\s]+)')


def extract_urls(text):
    return url_regex.findall(text)


# Check if any URL in the message is malicious
def message_contains_malicious_url(message):
    try:
        urls_in_message = extract_urls(message.content)
        for url in urls_in_message:
            if url in malicious_urls:
                return True, url
        return False, None
    except Exception as e:
        print(f"Error checking malicious URLs: {e}")
        return False, None


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
        try:
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
                new_row.to_csv(file_path, index=False)

            await interaction.followup.send(
                "Reported to Amber's database. Thank you for helping make Discord a better place for everyone.",
                ephemeral=True)
        except Exception as e:
            print(f"Error in report button: {e}")
            await interaction.followup.send("An error occurred while submitting the report.", ephemeral=True)


@bot.event
async def on_ready():
    print(f"{bot.user} is ready and online!")


@bot.event
async def on_guild_join(ctx):
    try:
        guild = await bot.fetch_guild(ctx.id)
        embed = discord.Embed(title=f"Thank you for adding Amber to {guild.name}", color=discord.Color(0xeeba2b))
        embed.add_field(name="Setup",
                        value="Let's start the setup process! To start the setup, do /setup. You can also use this to edit settings.",
                        inline=False)

        target_channel = None
        for channel in ctx.text_channels:
            if channel.permissions_for(ctx.me).send_messages:
                target_channel = channel
                break

        if target_channel is not None:
            await target_channel.send(embed=embed)
        else:
            print("No channel to send the message to!")
    except Exception as e:
        print(f"Error in on_guild_join: {e}")


@bot.event
async def on_message(message: discord.Message):
    try:
        # Ignore the bot's own messages
        if message.author == bot.user:
            return

        # Check for malicious content
        await check_mal_url(message)
        await check_mal_url_ending(message)
        await check_mal_term(message)

        # Check URLhaus malicious URLs
        contains_malicious, malicious_url = message_contains_malicious_url(message)
        if contains_malicious:
            try:
                await message.reply("⚠️ Message was flagged for containing a malicious link.")
                await message.delete()
            except (discord.NotFound, discord.HTTPException):
                # Message was already deleted or doesn't exist
                pass

            await send_to_mod_channel(message, "Malicious Link Detected")

        # Check if it's a reply with bot mention (reporting system)
        if message.reference is not None and bot.user in message.mentions:
            try:
                replied_message = await message.channel.fetch_message(message.reference.message_id)

                if replied_message.author == bot.user:
                    return

                # Send report to mod channel
                try:
                    settings_df = pd.read_csv("settings.csv")
                    user_row = settings_df[settings_df["guild"] == message.guild.id]
                    if not user_row.empty:
                        channel_id = user_row.iloc[0]["mod_channel"]

                        embed = discord.Embed(title="User Report", color=discord.Color(0xeeba2b))
                        embed.add_field(name="Reported By: ", value=str(message.author), inline=False)
                        embed.add_field(name="Reported Message: ", value=str(replied_message.content), inline=False)
                        embed.add_field(name="User Reported: ", value=str(replied_message.author), inline=False)
                        embed.add_field(name="Reason: ", value=str(message.content), inline=False)

                        view = ReportButton(message.author.id, replied_message.author.id, message.content,
                                            replied_message.content)

                        try:
                            await bot.get_channel(int(channel_id)).send(embed=embed, view=view)
                            await message.reply("Message Successfully Reported!")
                        except (discord.Forbidden, discord.NotFound):
                            await message.reply("Unable to send report to mod channel. Please check bot permissions.")
                        except discord.HTTPException as e:
                            await message.reply("An error occurred while sending the report.")
                except FileNotFoundError:
                    await message.reply("Bot not set up for this server. Please run /setup first.")
            except discord.NotFound:
                await message.reply("The message you're trying to report no longer exists.")
            except Exception as e:
                print(f"Error in reporting system: {e}")
    except Exception as e:
        print(f"Error in on_message: {e}")


@bot.command(name="debug", description="Sends a debug report")
async def debug(ctx):
    try:
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
        embed.add_field(name="<:peep:1408020069400969236> Are the squirrels asking you to do this?", value=" ", inline=False)
        embed.add_field(name="Ping", value=f"{latency}ms", inline=False)
        embed.add_field(name="Integration Type", value="User", inline=False)
        embed.add_field(name="Context", value="Guild", inline=False)
        embed.add_field(name="Shard ID", value=f"{ctx.guild.shard_id}", inline=False)
        embed.add_field(name="Guild ID", value=f"{ctx.guild.id}", inline=False)
        embed.add_field(name="Channel ID", value=f"{ctx.channel.id}", inline=False)
        embed.add_field(name="Author ID", value=f"{ctx.author.id}", inline=False)
        embed.add_field(name="CPU", value=f"{cpu_percent}%", inline=False)
        embed.add_field(name="Memory", value=f"{memory_used} MB Used / {memory_total} GB", inline=False)
        embed.add_field(name="Malicious URLs Loaded", value=f"{len(malicious_urls)}", inline=False)

        # Add a footer with the current date and time
        embed.set_footer(text=f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        await ctx.respond(embed=embed, ephemeral=True)
    except Exception as e:
        await ctx.respond(f"Error generating debug info: {e}", ephemeral=True)


@bot.command(name="setup", description="Sets up / edits the server settings")
@commands.has_permissions(administrator=True)
@option("mod_channel", discord.TextChannel, description="Your Mod Channel")
@option("mod_role", discord.Role, description="Pick a mod role")
async def setup(ctx: discord.ApplicationContext, mod_channel: discord.TextChannel, mod_role: discord.Role):
    try:
        # Create settings.csv if it doesn't exist
        file_path = "settings.csv"
        if not os.path.exists(file_path):
            empty_df = pd.DataFrame(columns=["guild", "mod_channel", "mod_role"])
            empty_df.to_csv(file_path, index=False)

        df = pd.read_csv(file_path)

        if ctx.guild.id not in df["guild"].values:
            # Add new server
            data = {
                "guild": [ctx.guild.id],
                "mod_channel": [mod_channel.id],
                "mod_role": [mod_role.id]
            }
            new_row = pd.DataFrame(data)
            df = pd.concat([df, new_row], ignore_index=True)
            df.to_csv(file_path, index=False)
            await ctx.respond("Amber set up! Enjoy a streamlined reporting workflow and spam filters!")
        else:
            # Update existing server
            df.loc[df["guild"] == ctx.guild.id, "mod_channel"] = mod_channel.id
            df.loc[df["guild"] == ctx.guild.id, "mod_role"] = mod_role.id
            df.to_csv(file_path, index=False)
            await ctx.respond("Settings updated successfully!")
    except Exception as e:
        await ctx.respond(f"An error occurred during setup: {e}")


try:
    token = dotenv.get_key(key_to_get='DISCORD_TOKEN', dotenv_path='.env')
    if not token:
        print("Discord token not found in .env file")
        sys.exit(1)
    bot.run(token)
except discord.LoginFailure:
    print("Invalid Discord token.")
except discord.HTTPException:
    print("Network error occurred.")
except Exception as e:
    print(f"Unexpected error: {e}")