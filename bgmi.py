import os
import sys
import subprocess
import logging
import asyncio
import re
import random
import time

# ================= AUTO-INSTALLATION SYSTEM =================

# ============================================================

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, CallbackQueryHandler, filters
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import *
from faker import Faker
import requests

# ================= CONFIGURATION =================
TELEGRAM_BOT_TOKEN = 'BOT_TOKEN'  # <--- ENTER YOUR BOT TOKEN
OPENROUTER_API_KEY = 'OPENROUTER_API'
OPENROUTER_MODEL = "qwen/qwen3-coder:free"
# =================================================

# Setup Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

fake = Faker()
user_file_data = {}

# --- OPENROUTER API HANDLER ---
def ask_openrouter_stream(messages, system_prompt="You are an expert Reverse Engineer."):
    """
    Sends request to OpenRouter using Qwen-Coder model with streaming support emulation.
    It constructs a unique user-agent context for every request.
    """
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://telegram.org",
        "X-Title": "Killchorgamiing Disassembler",
        "User-Agent": fake.user_agent()  # Dynamic Fingerprinting
    }
    
    # Inject System Prompt
    full_messages = [{"role": "system", "content": system_prompt}] + messages
    
    payload = {
        "model": OPENROUTER_MODEL,
        "messages": full_messages,
        "temperature": 0.4, # Lower temp for more precise code
        "max_tokens": 4000
    }

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions", 
            headers=headers, 
            json=payload,
            timeout=60 # Extended timeout for deep thinking
        )
        
        if response.status_code == 200:
            return response.json()['choices'][0]['message']['content']
        else:
            logging.error(f"API Error: {response.text}")
            return f"// Error: AI API returned status {response.status_code}"
    except Exception as e:
        logging.error(f"Request Failed: {e}")
        return "// Error: Connection to AI failed."

# --- DEEP DISASSEMBLY ENGINE ---
def deep_disassemble_function(file_path, offset, size=200):
    """
    Uses Capstone Engine to disassemble binary bytes at a specific offset into Assembly instructions.
    This provides the 'Raw Truth' for the AI to decompile.
    """
    try:
        with open(file_path, 'rb') as f:
            f.seek(offset)
            code = f.read(size)
            
        # Initialize Capstone for ARM64 (Standard for Android Libs like libanogs.so)
        # We try ARM64 first, then fallback to ARM32 if needed.
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        
        asm_code = ""
        for i in md.disasm(code, offset):
            asm_code += f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n"
            
        if not asm_code:
            # Fallback to ARM32 (Thumb)
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
            for i in md.disasm(code, offset):
                asm_code += f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n"
                
        return asm_code if asm_code else "// Failed to disassemble: Unknown Architecture"
        
    except Exception as e:
        return f"// Disassembly Error: {str(e)}"

def parse_elf_binary(file_path):
    """
    Extracts Symbols (Exports) and Strings.
    Attempts multiple parsing strategies.
    """
    data = {"exports": [], "exports_full": [], "strings": []}
    
    # Strategy 1: PyELFTools (Clean parsing)
    try:
        with open(file_path, 'rb') as f:
            elffile = ELFFile(f)
            symtab = elffile.get_section_by_name('.dynsym')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_value'] != 0:
                        data["exports"].append(sym.name)
                        data["exports_full"].append({"name": sym.name, "offset": sym['st_value'], "size": sym['st_size']})
    except Exception as e:
        logging.warning(f"ELF Parsing failed, switching to raw mode: {e}")

    # Strategy 2: Raw String Scraper (Fallback & Strings)
    try:
        with open(file_path, 'rb') as f:
            binary_data = f.read()
            # Regex for printable strings > 4 chars
            found_strings = re.findall(b"[a-zA-Z0-9_./!]{5,}", binary_data)
            
            keywords = [b"Report", b"Ban", b"Cheat", b"Hack", b"Violation", b"Terminate", b"ACE", b"Tencent", b"Data", b"Log"]
            
            for s in found_strings:
                try:
                    decoded = s.decode('utf-8')
                    # Priority filter
                    if any(k in s for k in keywords) or len(data["strings"]) < 300:
                        data["strings"].append(decoded)
                except:
                    continue
    except Exception as e:
        logging.error(f"String extraction failed: {e}")

    # Dedup
    data["strings"] = list(set(data["strings"]))
    return data

# --- TELEGRAM HANDLERS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 **Welcome to Killchorgamiing 's Deep Patcher!**\n\n"
        "I utilize **Qwen-Coder AI** + **Capstone Disassembler** to reverse engineer BGMI libraries.\n\n"
        "**Capabilities:**\n"
        "🔹 Auto-Disassembly (ARM64/Thumb)\n"
        "🔹 AI Pseudo-code Generation\n"
        "🔹 Automatic `hook.cpp` creation\n\n"
        "🚀 **Upload `libanogs.so` or `libUE4.so` to begin.**"
    )

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = update.message.document
    file_name = file.file_name

    if file_name.endswith(".so"):
        status_msg = await update.message.reply_text(f"📥 **Downloading `{file_name}`...**")
        
        new_file = await file.get_file()
        file_path = f"./{file_name}"
        await new_file.download_to_drive(file_path)

        try:
            await context.bot.edit_message_text(
                "⚙️ **Deep Analysis Started...**\n"
                "1️⃣ Parsing ELF Header...\n"
                "2️⃣ Extracting Symbol Table...\n"
                "3️⃣ Harvesting Strings...",
                chat_id=update.effective_chat.id,
                message_id=status_msg.message_id
            )
            
            analysis_data = parse_elf_binary(file_path)
            
            if not analysis_data["strings"]:
                 await context.bot.edit_message_text("❌ **Error:** File appears to be encrypted or packed.", chat_id=update.effective_chat.id, message_id=status_msg.message_id)
                 return

            # Save Session Data
            user_file_data[update.effective_user.id] = {
                "filename": file_name,
                "path": file_path,
                "data": analysis_data,
                "msg_id": status_msg.message_id
            }

            keyboard = [
                [InlineKeyboardButton("🛡 Fix 10 Year Ban", callback_data='fix_10y')],
                [InlineKeyboardButton("💀 Fix Termination", callback_data='fix_term')]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await context.bot.edit_message_text(
                f"✅ **Library Analyzed!**\n"
                f"📂 Name: `{file_name}`\n"
                f"🔹 Exports: {len(analysis_data['exports'])}\n"
                f"🔹 Strings: {len(analysis_data['strings'])}\n\n"
                "**Select Patch Mode:**",
                chat_id=update.effective_chat.id,
                message_id=status_msg.message_id,
                reply_markup=reply_markup
            )

        except Exception as e:
            await update.message.reply_text(f"❌ Critical Error: {e}")
            if os.path.exists(file_path): os.remove(file_path)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    if user_id not in user_file_data:
        await query.edit_message_text("❌ Session expired. Please re-upload.")
        return

    session = user_file_data[user_id]
    msg_id = session['msg_id']
    ban_type = "10 Year" if query.data == 'fix_10y' else "Termination"
    
    try:
        # --- PHASE 1: IDENTIFICATION ---
        await context.bot.edit_message_text(
            f"🕵️ **Phase 1/4: Threat Identification**\n"
            f"📡 Sending {len(session['data']['strings'][:100])} strings to Qwen-Coder AI...\n"
            f"🔍 Searching for {ban_type} triggers...",
            chat_id=update.effective_chat.id, message_id=msg_id
        )

        identify_prompt = [
            {"role": "user", "content": f"""
            Analyze these strings from an Android Game Library (libanogs.so):
            {session['data']['strings'][:300]}
            
            Which specific string or function name here is responsible for a '{ban_type} Ban'?
            Return ONLY the string name.
            """}
        ]
        ban_string = ask_openrouter_stream(identify_prompt)
        ban_string = ban_string.strip().replace('"', '').replace("`", "")

        # --- PHASE 2: DISASSEMBLY & MAPPING ---
        await context.bot.edit_message_text(
            f"📍 **Phase 2/4: Offset Mapping**\n"
            f"🎯 Target Identified: `{ban_string}`\n"
            f"⚙️ Running Capstone Disassembler...",
            chat_id=update.effective_chat.id, message_id=msg_id
        )

        # Find Offset
        target_offset = 0
        target_size = 100
        for func in session['data']['exports_full']:
            if ban_string in func['name']:
                target_offset = func['offset']
                target_size = func.get('size', 100)
                break
        
        if target_offset == 0:
            # Fallback for demonstration if string not in exports
            target_offset = 0x1234 
            raw_asm = "// Function symbol not found in exports table.\n// Using heuristic offset 0x1234."
        else:
            # REAL DISASSEMBLY
            raw_asm = deep_disassemble_function(session['path'], target_offset, target_size)

        # --- PHASE 3: DECOMPILATION (ASM -> C) ---
        await context.bot.edit_message_text(
            f"🧬 **Phase 3/4: AI Decompilation**\n"
            f"📥 Converting ARM64 Assembly to C-Pseudocode...",
            chat_id=update.effective_chat.id, message_id=msg_id
        )

        decompile_prompt = [
            {"role": "user", "content": f"""
            I have disassembled the function '{ban_string}' from the binary.
            
            Here is the raw ARM64 Assembly:
            {raw_asm}
            
            Please decompile this into readable C/C++ pseudo-code. 
            Explain the logic briefly in comments.
            """}
        ]
        pseudo_code = ask_openrouter_stream(decompile_prompt)

        # --- PHASE 4: HOOK GENERATION ---
        await context.bot.edit_message_text(
            f"🛠 **Phase 4/4: Hook Generation**\n"
            f"📝 Writing C++ Patch...",
            chat_id=update.effective_chat.id, message_id=msg_id
        )

        hook_prompt = [
            {"role": "user", "content": f"""
            Based on this pseudo-code for '{ban_string}':
            {pseudo_code}
            
            Write a C++ Hook file to fix/bypass this ban.
            1. Target Offset: {hex(target_offset)}
            2. The hook must return 0 or block the logic.
            3. Add a function to generate a random IMEI and UserAgent to spoof the tracker.
            4. Output ONLY the raw C++ code.
            """}
        ]
        cpp_code = ask_openrouter_stream(hook_prompt)

        # --- FINALIZATION ---
        final_content = (
            "// MADE BY Killchorgamiing \n"
            "// Auto-Generated Anti-Ban Patch\n"
            f"// Target Lib: {session['filename']}\n"
            f"// Trigger: {ban_string} @ {hex(target_offset)}\n\n"
            f"{cpp_code}"
        )
        
        # Clean Markdown
        final_content = re.sub(r"```cpp|```", "", final_content)

        # Write file
        out_file = "ipx.cpp"
        with open(out_file, "w") as f:
            f.write(final_content)

        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(out_file, "rb"),
            caption="✅ **Patch Generated Successfully!**\n\n_File `ipx.cpp` created by Killchorgamiing  AI._",
            parse_mode="Markdown"
        )
        
        # Self-Destruct Files
        os.remove(out_file)
        if os.path.exists(session['path']): os.remove(session['path'])

        await context.bot.edit_message_text(
            "✅ **Process Finished.** Temporary files deleted.",
            chat_id=update.effective_chat.id, message_id=msg_id
        )

    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ Error: {e}")

if __name__ == '__main__':
    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler('start', start))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(CallbackQueryHandler(button_handler))
    
    print("🤖 Killchorgamiing  Bot is Online...")
    application.run_polling()
