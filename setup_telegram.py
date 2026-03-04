#!/usr/bin/env python3
"""
Telegram Chat Setup and Testing for AI-NIDS
===========================================
This script helps you set up and test Telegram notifications for your AI-NIDS system.
"""

import os
import sys
import requests
import json
from datetime import datetime

def check_telegram_config():
    """Check current Telegram configuration."""
    print("🔍 Checking Telegram configuration...")

    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')

    if not bot_token:
        print("❌ TELEGRAM_BOT_TOKEN not set")
        return False
    else:
        print("✅ TELEGRAM_BOT_TOKEN is configured")

    if not chat_id:
        print("❌ TELEGRAM_CHAT_ID not set")
        return False
    else:
        print("✅ TELEGRAM_CHAT_ID is configured")

    return True

def test_telegram_bot():
    """Test Telegram bot connectivity."""
    print("\n🤖 Testing Telegram bot...")

    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    if not bot_token:
        print("❌ No bot token available")
        return False

    try:
        # Test bot info
        url = f"https://api.telegram.org/bot{bot_token}/getMe"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            bot_info = response.json()
            if bot_info.get('ok'):
                bot_name = bot_info['result'].get('first_name', 'Unknown')
                print(f"✅ Bot connected: {bot_name}")
                return True
            else:
                print(f"❌ Bot API error: {bot_info}")
                return False
        else:
            print(f"❌ HTTP error: {response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

def send_test_message():
    """Send a test message to Telegram chat."""
    print("\n📤 Sending test message...")

    bot_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    chat_id = os.environ.get('TELEGRAM_CHAT_ID')

    if not bot_token or not chat_id:
        print("❌ Missing bot token or chat ID")
        return False

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        message = {
            "chat_id": chat_id,
            "text": f"🔔 AI-NIDS Test Message\n\n🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nYour AI-NIDS Telegram notifications are working! 🎉",
            "parse_mode": "HTML"
        }

        response = requests.post(url, json=message, timeout=10)

        if response.status_code == 200:
            result = response.json()
            if result.get('ok'):
                print("✅ Test message sent successfully!")
                print("📱 Check your Telegram chat for the message.")
                return True
            else:
                print(f"❌ Telegram API error: {result}")
                return False
        else:
            print(f"❌ HTTP error: {response.status_code}")
            print(f"Response: {response.text}")
            return False

    except Exception as e:
        print(f"❌ Error sending message: {e}")
        return False

def setup_telegram_guide():
    """Provide step-by-step setup guide."""
    print("\n" + "="*60)
    print("📚 TELEGRAM SETUP GUIDE")
    print("="*60)

    print("""
🔧 How to set up Telegram notifications:

1️⃣ Create a Telegram Bot:
   • Open Telegram and search for @BotFather
   • Send: /newbot
   • Follow instructions to create your bot
   • Save the bot token (starts with '123456:ABC-...')

2️⃣ Get your Chat ID:
   • Start a chat with your bot
   • Send any message to activate it
   • Visit: https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
   • Find your chat ID in the response

3️⃣ Set Environment Variables:
   export TELEGRAM_BOT_TOKEN="your_bot_token_here"
   export TELEGRAM_CHAT_ID="your_chat_id_here"

4️⃣ Test the setup:
   python setup_telegram.py

5️⃣ For production, add to your .env file:
   TELEGRAM_BOT_TOKEN=your_bot_token_here
   TELEGRAM_CHAT_ID=your_chat_id_here

📱 Example .env entries:
   TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
   TELEGRAM_CHAT_ID=123456789

🚨 Troubleshooting:
   • Make sure your bot token starts with a number
   • Chat ID should be a number (can be negative for groups)
   • Test with the script above before deploying
   • Check firewall if messages aren't sending
""")

def main():
    """Main setup and testing function."""
    print("🔔 AI-NIDS Telegram Chat Setup")
    print("="*40)

    # Check configuration
    config_ok = check_telegram_config()

    if not config_ok:
        print("\n⚠️  Telegram not configured. Follow the setup guide below:")
        setup_telegram_guide()
        return

    # Test bot connectivity
    bot_ok = test_telegram_bot()

    if not bot_ok:
        print("\n❌ Bot test failed. Check your bot token.")
        setup_telegram_guide()
        return

    # Send test message
    message_ok = send_test_message()

    if message_ok:
        print("\n🎉 Telegram setup complete!")
        print("📢 Your AI-NIDS will now send alerts to Telegram.")
    else:
        print("\n❌ Message test failed. Check your chat ID.")
        setup_telegram_guide()

if __name__ == "__main__":
    main()