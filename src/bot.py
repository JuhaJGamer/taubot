#!/usr/bin/env python3

import praw
import discord
import json
import time
import asyncio
import traceback
from aiohttp import web
from accounting import LedgerServer, Authorization, RedditAccountId, DiscordAccountId, AccountId
from commands import COMMANDS, list_commands_as_markdown, CommandException, assert_authorized, process_command
from utils import split_into_chunks, discord_postprocess
from httpapi import RequestServer
import httpv2

# move this to config?
prefix = "e!"

def read_config():
    """Reads the configuration file."""
    with open('bot-config.json') as f:
        return json.load(f)

def create_reddit(config):
    """Creates a Reddit handle."""
    return praw.Reddit(
        client_id=config['reddit_client_id'],
        client_secret=config['reddit_client_secret'],
        user_agent='PyEng Bot 0.1',
        username=config['reddit_username'],
        password=config['reddit_password'])

def reply(message, body):
    """Replies to a private message."""
    title = message.subject
    if not title.lower().startswith('re:'):
        title = 're: %s' % message.subject
    message.mark_read()
    return message.author.message(title, '%s\n\n%s\n\n%s' % ('\n'.join('> %s' % line for line in message.body.split('\n')), body, 'Provided by r/SimDemocracy'))

def process_message(message, server):
    """Processes a message sent to the bot."""
    reply(message, process_command(RedditAccountId(message.author.name), message.body, server))

def process_all_messages(reddit, server):
    """Processes all unread messages received by the bot."""
    # Process private messages.
    for message in reddit.inbox.unread(limit=None):
        process_message(message, server)

def is_comment_replied_to(reddit, comment):
    comment.refresh()
    for reply in comment.replies:
        if reply.author == reddit.user.me():
            return True
    return False

def process_comment(comment, server):
    """Processes a comment with the proper prefix."""
    author = RedditAccountId(comment.author.name)
    comment.reply(process_command(author, comment.body[len(prefix):], server))

async def message_loop(reddit, server):
    """The bot's main Reddit message loop."""
    while True:
        # Process messages.
        try:
            process_all_messages(reddit, server)
        except Exception:
            traceback.print_exc()

        # Sleep for five seconds.
        await asyncio.sleep(5)

async def tick_loop(server):
    """The bot's tick loop, which looks at the clock every now and then and notifies the
       server when a tick has elapsed."""
    # Let's make a tick twice every day.
    tick_duration = 12 * 60 * 60

    while True:
        # Notify the server that one or more ticks have elapsed if necessary.
        while int(time.time() - server.last_tick_timestamp) > tick_duration:
            server.notify_tick_elapsed(server.last_tick_timestamp + tick_duration)

        # Sleep for a while.
        await asyncio.sleep(5)

async def comment_loop(reddit, server):
    """The bot's main Reddit comment loop."""
    # TODO: handle multiple subreddits.
    for comment in reddit.subreddit('simeconomy').stream.comments(pause_after=0):
        # Prcoess next comment if necessary.
        if not (comment is None or is_comment_replied_to(reddit, comment)):
            if comment.body.startswith(prefix):
                process_comment(comment, server)
                await asyncio.sleep(10 * 60)

        # Sleep for five seconds.
        await asyncio.sleep(5)

if __name__ == '__main__':
    # config = read_config()
    # reddit = create_reddit(config)
    # discord_client = discord.Client()

    # @discord_client.event
    # async def on_message(message):
    #     if message.author == discord_client.user:
    #         return

    #     content = message.content.lstrip()
    #     prefixes = (
    #         '<@%s>' % discord_client.user.id,
    #         '<@!%s>' % discord_client.user.id,
    #         'e!')

    #     if content.startswith(prefixes): # Checking all messages that start with the prefix.
    #         prefix = [prefix for prefix in prefixes if content.startswith(prefix)][0]
    #         command_content = content[len(prefix):].lstrip()
    #         response = discord_postprocess(
    #             process_command(
    #                 DiscordAccountId(str(message.author.id)),
    #                 command_content,
    #                 server,
    #                 prefixes[0] + ' '))

    #         chunks = split_into_chunks(response.encode('utf-8'), 1024)
    #         embed = discord.Embed(color=0x3b4dff)
    #         title = command_content.split()[0] if len(command_content.split()) > 0 else 'Empty Message'
    #         for i, chunk in enumerate(chunks):
    #             title = "(cont'd)" if i > 0 else title
    #             embed.add_field(name=title, value=chunk.decode('utf-8'), inline=False)

    #         embed.set_thumbnail(url=message.author.avatar_url)
    #         embed.set_footer(text="This was sent in response to %s's message; you can safely disregard it if that's not you." % message.author.name)

    #         await message.channel.send(embed=embed)

    with LedgerServer('ledger.txt') as server:
        loop = asyncio.get_event_loop()

        # # Run the Reddit bot.
        # asyncio.get_event_loop().create_task(tick_loop(server))
        # asyncio.get_event_loop().create_task(message_loop(reddit, server))
        # asyncio.get_event_loop().create_task(comment_loop(reddit, server))

        # Run the HTTP server.
        app = web.Application()
        app.router.add_get('/api/v1/', RequestServer(server, None).handle_request)
        api = httpv2.RestApi('/api/v2/',app.router, server)
        loop.create_task(web._run_app(app,port=8888))

        # # Run the Discord bot.
        # if 'discord_token' in config:
        #     discord_client.run(config['discord_token'])
        # else:
        #     asyncio.get_event_loop().run_forever()
        asyncio.get_event_loop().run_forever()
