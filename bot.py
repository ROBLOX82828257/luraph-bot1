import discord
from discord.ext import commands
import json
import os
import tempfile
import shutil
import asyncio
import logging

from deobfuscator.pipeline import DeobfuscationPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

with open('config.json', 'r') as f:
    config = json.load(f)

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=config.get('prefix', '!'), intents=intents)
pipeline = DeobfuscationPipeline()

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25MB
ALLOWED_EXTENSIONS = {'.lua', '.txt'}

@bot.event
async def on_ready():
    logger.info(f'Logged in as {bot.user} (ID: {bot.user.id})')
    logger.info(f'Connected to {len(bot.guilds)} guild(s)')
    await bot.change_presence(activity=discord.Game(name="!deobf | Luraph Deobfuscator"))

@bot.command(name='deobf')
async def deobfuscate(ctx):
    if not ctx.message.attachments:
        await ctx.send("Attach a `.lua` or `.txt` file to deobfuscate. Usage: `!deobf` with a file attached.")
        return

    attachment = ctx.message.attachments[0]
    file_ext = os.path.splitext(attachment.filename)[1].lower()

    if file_ext not in ALLOWED_EXTENSIONS:
        await ctx.send(f"Unsupported file type `{file_ext}`. Only `.lua` and `.txt` files are accepted.")
        return

    if attachment.size > MAX_FILE_SIZE:
        await ctx.send(f"File too large ({attachment.size // 1024} KB). Max allowed: {MAX_FILE_SIZE // (1024 * 1024)} MB.")
        return

    status_msg = await ctx.send(f"📥 Downloading `{attachment.filename}`...")

    work_dir = tempfile.mkdtemp(prefix='luraph_deobf_')
    input_path = os.path.join(work_dir, attachment.filename)
    output_filename = f"deobfuscated_{attachment.filename}"
    output_path = os.path.join(work_dir, output_filename)

    try:
        await attachment.save(input_path)
        logger.info(f"Saved {attachment.filename} ({attachment.size} bytes) from {ctx.author}")

        await status_msg.edit(content="🔍 Detecting Luraph obfuscation...")

        with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
            source = f.read()

        if not pipeline.detector.is_luraph(source):
            await status_msg.edit(content="⚠️ This file doesn't appear to be Luraph-obfuscated. Proceeding anyway...")

        await status_msg.edit(content="🔧 Deobfuscating — this may take a moment depending on file complexity...")

        result = await asyncio.to_thread(pipeline.deobfuscate, source)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)

        await status_msg.edit(content="✅ Deobfuscation complete. Uploading result...")

        with open(output_path, 'rb') as f:
            discord_file = discord.File(f, filename=output_filename)
            await ctx.send(file=discord_file, content=f"Here's the deobfuscated output for `{attachment.filename}`")

        await status_msg.delete()

        logger.info(f"Successfully deobfuscated {attachment.filename} for {ctx.author}")

    except Exception as e:
        logger.error(f"
