/* ================================================
   NexaBot – Chatbot Logic
   CodeAlpha Internship Task 4: AI Chatbot
   Domain: Cloud Computing

   FILE: assets/js/chatbot.js

   ARCHITECTURE OVERVIEW:
   ┌─────────────────────────────────────────────┐
   │              User Input                      │
   └─────────────────┬───────────────────────────┘
                     │
                     ▼
   ┌─────────────────────────────────────────────┐
   │     STEP 1: Pattern Matching Engine          │
   │     (Retrieval-Based — instant, free)        │
   │     Checks if query matches known intents    │
   └─────────────────┬───────────────────────────┘
                     │ No match found?
                     ▼
   ┌─────────────────────────────────────────────┐
   │     STEP 2: Claude AI API Call               │
   │     (Generative — intelligent, flexible)     │
   │     Handles anything the patterns can't      │
   └─────────────────────────────────────────────┘

   WHY HYBRID APPROACH?
   - Pattern matching = instant response, 0 cost,
     works offline, perfect for known FAQs
   - Generative AI = handles unexpected questions,
     provides human-like contextual responses
   This is how enterprise chatbots actually work.
================================================ */


/* ================================================
   PART 1: PREDEFINED TRAINING PATTERNS
   
   WHY THIS APPROACH?
   These are the "trained patterns" the task requires.
   Each entry has:
   - patterns[]: keywords that trigger this response
   - response: the text to show the user
   - chips[]: follow-up quick reply suggestions

   In a real product, these would come from a
   database or CMS — making them easy to update
   without touching code.
================================================ */

const KNOWLEDGE_BASE = [
  {
    id: "greeting",
    patterns: ["hello", "hi", "hey", "good morning", "good afternoon",
               "good evening", "howdy", "greetings", "what's up", "sup"],
    response: "👋 Hello! Welcome to **NexaShop**. I'm NexaBot, your AI assistant.\n\nI can help you with:\n• Product information\n• Order tracking\n• Pricing & plans\n• Technical support\n\nWhat can I help you with today?",
    chips: ["View Products", "Check Pricing", "Track My Order"]
  },
  {
    id: "products",
    patterns: ["product", "what do you sell", "catalog", "items", "offer",
               "buy", "purchase", "what can i get", "services", "range"],
    response: "🛍️ We offer three main product lines:\n\n• **NexaPro** – Professional software tools & licenses\n• **NexaHome** – Smart home devices & IoT products\n• **NexaWear** – Wearable technology & accessories\n\nAll products include:\n✅ 30-day money-back guarantee\n✅ Free shipping on orders over $50\n✅ 1-year warranty",
    chips: ["See Pricing", "Place an Order", "Return Policy"]
  },
  {
    id: "pricing",
    patterns: ["price", "pricing", "cost", "how much", "plan", "plans",
               "subscription", "fee", "charge", "rate", "affordable", "cheap"],
    response: "💰 Our pricing plans:\n\n🆓 **Starter** – Free forever\n   → 5 products, basic support\n\n💼 **Growth** – $29/month\n   → Unlimited products, email support\n\n🚀 **Pro** – $79/month\n   → Everything + priority support + AI features\n\n🏢 **Enterprise** – Custom pricing\n   → Dedicated account manager\n\nAll paid plans include a **14-day free trial** — no credit card needed!",
    chips: ["Start Free Trial", "Compare Plans", "Contact Sales"]
  },
  {
    id: "orders",
    patterns: ["order", "track", "tracking", "shipping", "delivery", "package",
               "where is my", "status", "shipped", "dispatch", "arrive", "when will"],
    response: "📦 To track your order:\n\n1️⃣ Log into your account dashboard\n2️⃣ Click **'My Orders'** in the sidebar\n3️⃣ Select your order to see real-time tracking\n\n**Shipping times:**\n• Standard: 3–5 business days\n• Express: 1–2 business days\n• International: 7–14 business days\n\nYou'll receive automatic SMS and email updates with your tracking number.",
    chips: ["Open Dashboard", "Contact Support", "Return an Item"]
  },
  {
    id: "support",
    patterns: ["support", "help", "problem", "issue", "bug", "technical",
               "broken", "error", "not working", "fix", "trouble", "contact"],
    response: "🔧 I'm here to help! Support options:\n\n💬 **AI Chat (me!)** — Available 24/7, instant responses\n📧 **Email** — support@nexashop.com (reply in 2 hours)\n📞 **Phone** — 1-800-NEXA-BOT (Mon–Fri, 9AM–6PM EST)\n📖 **Knowledge Base** — docs.nexashop.com\n\nFor urgent production issues, Pro & Enterprise customers get **emergency escalation**.\n\nCan you describe your specific issue so I can assist directly?",
    chips: ["Common Fixes", "Submit Ticket", "Knowledge Base"]
  },
  {
    id: "hours",
    patterns: ["hour", "hours", "open", "working hours", "available", "when",
               "time", "schedule", "operating", "business hours"],
    response: "🕐 **Availability:**\n\n🤖 **NexaBot (AI)** — 24/7/365, never sleeps!\n👥 **Human Agents** — Mon–Fri, 9AM–6PM EST\n🚨 **Emergency Line** — Pro & Enterprise only\n\n**Response time targets:**\n• Chat: Under 30 seconds\n• Email: Under 2 hours\n• Phone: Under 5 minutes\n\nFor the fastest help, you're already in the right place — just ask me!",
    chips: ["Contact Now", "Schedule a Call", "Leave a Message"]
  },
  {
    id: "returns",
    patterns: ["refund", "return", "cancel", "money back", "policy",
               "exchange", "replacement", "warranty", "guarantee", "damaged"],
    response: "↩️ Our hassle-free return policy:\n\n• **30-day** money-back guarantee, no questions asked\n• **Free return shipping** on all domestic orders\n• Refunds processed within **3–5 business days**\n• **Exchanges** available for size/color changes\n\nFor damaged or defective products:\n→ Contact us within **48 hours** with photos\n→ We'll ship a replacement immediately\n\nTo start a return: My Account → Orders → Request Return",
    chips: ["Start a Return", "Check Refund Status", "Talk to Agent"]
  },
  {
    id: "account",
    patterns: ["account", "login", "sign in", "sign up", "register",
               "password", "forgot", "profile", "settings", "username"],
    response: "👤 **Account Help:**\n\n**Can't log in?**\n→ Click 'Forgot Password' on the login page\n→ Check your email for the reset link (check spam!)\n→ Link expires after 24 hours\n\n**New user?**\n→ Visit nexashop.com/register\n→ Free account takes 30 seconds\n\n**Update your profile:**\n→ Dashboard → Settings → Profile\n\nStill having trouble? Share your registered email and I'll escalate to our team.",
    chips: ["Reset Password", "Create Account", "Contact Support"]
  },
  {
    id: "farewell",
    patterns: ["bye", "goodbye", "see you", "thanks", "thank you",
               "that's all", "done", "that's it", "all good", "cheers"],
    response: "😊 You're very welcome! It was a pleasure assisting you.\n\nRemember, I'm here **24/7** whenever you need help. Have a wonderful day! ✨\n\n⭐ If I was helpful, feel free to rate your experience!",
    chips: []
  }
];


/* ================================================
   PART 2: APPLICATION STATE
   
   WHY TRACK STATE?
   - conversationHistory: Sent to Claude API each time
     so it has context of the full conversation
   - apiKey: Stored for duration of session
   - isTyping: Prevents sending multiple messages
     while waiting for a response (prevents spam)
   - chatOpen: Tracks panel visibility for toggle
================================================ */

let conversationHistory = [];
let apiKey              = null;
let isDemoMode          = false;
let isTyping            = false;
let chatOpen            = false;
let messageCount        = 0;


/* ================================================
   PART 3: API KEY MANAGEMENT

   WHY sessionStorage AND NOT localStorage?
   - localStorage persists FOREVER until cleared
   - sessionStorage clears when the tab/browser closes
   - For security credentials like API keys,
     sessionStorage is far safer. If someone borrows
     your laptop, their session won't have your key.
================================================ */

function saveApiKey() {
  const key = document.getElementById('api-key-input').value.trim();

  if (!key) {
    showModalError('Please enter your API key first.');
    return;
  }

  if (!key.startsWith('sk-ant')) {
    showModalError('Invalid key format. Anthropic keys start with "sk-ant".');
    return;
  }

  apiKey = key;
  sessionStorage.setItem('nexabot_key', key);
  closeModal();
  initChat(false);
}

function skipApiKey() {
  isDemoMode = true;
  closeModal();
  initChat(true);
}

function closeModal() {
  const modal = document.getElementById('api-modal');
  modal.style.opacity = '0';
  modal.style.transition = 'opacity 0.3s ease';
  setTimeout(() => { modal.style.display = 'none'; }, 300);
}

function showModalError(msg) {
  const input = document.getElementById('api-key-input');
  input.style.borderColor = '#f87171';
  input.placeholder = msg;
  input.value = '';
  setTimeout(() => {
    input.style.borderColor = '';
    input.placeholder = 'sk-ant-api03-...';
  }, 2500);
}


/* ================================================
   PART 4: CHAT INITIALIZATION

   WHY SHOW A WELCOME MESSAGE?
   It tells the user:
   1. Who the bot is (NexaBot)
   2. What it can do (sets expectations)
   3. How to interact (suggests first actions)
   This is called "onboarding" — critical for
   user engagement with any chatbot.
================================================ */

function initChat(isDemo) {
  const demoNote = isDemo
    ? "\n\n⚠️ **Demo Mode** — I'll answer using predefined responses. For full AI capability, reload and enter your Anthropic API key."
    : "\n\n✅ **Claude AI is connected** — I can answer anything, even questions beyond my predefined knowledge!";

  const welcomeMsg = "👋 Hi! I'm **NexaBot**, your AI-powered customer assistant for NexaShop." + demoNote;

  appendBotMessage(welcomeMsg, ["What products do you offer?", "What are your pricing plans?", "How do I track my order?"]);
}


/* ================================================
   PART 5: PATTERN MATCHING ENGINE (Retrieval-Based)

   HOW IT WORKS:
   1. Convert user input to lowercase
   2. Loop through every entry in KNOWLEDGE_BASE
   3. Check if any keyword appears in the input
   4. If match found, return that entry immediately
   5. If no match, return null (triggers AI fallback)

   WHY DO THIS BEFORE CALLING THE API?
   - Pattern matches are INSTANT (no network call)
   - They're FREE (no API token cost)
   - They're RELIABLE (always same output)
   - They cover 70-80% of typical user queries
   - This keeps API costs low in production
================================================ */

function matchPattern(userText) {
  const lower = userText.toLowerCase().trim();

  for (const entry of KNOWLEDGE_BASE) {
    for (const keyword of entry.patterns) {
      if (lower.includes(keyword)) {
        return entry; // Found a match!
      }
    }
  }

  return null; // No match — will use AI
}


/* ================================================
   PART 6: CLAUDE AI API CALL (Generative Model)

   WHY CLAUDE (ANTHROPIC)?
   - State-of-the-art language model
   - Excellent at following instructions (system prompt)
   - Can maintain conversation context
   - Safe and commercially appropriate responses

   HOW THE SYSTEM PROMPT WORKS:
   The system prompt is like giving Claude a "job
   description". It constrains Claude to act as
   NexaShop's support agent, not as a general AI.
   This is called "prompt engineering" — a core
   skill in AI product development.

   WHY SEND FULL CONVERSATION HISTORY?
   Claude has NO memory between API calls. We must
   re-send the entire conversation each time so it
   has context to give relevant follow-up answers.
================================================ */

async function callClaudeAPI(userMessage) {
  // Add user message to history BEFORE calling API
  conversationHistory.push({
    role: "user",
    content: userMessage
  });

  const systemPrompt = `You are NexaBot, a friendly and professional AI customer support assistant for NexaShop — a modern e-commerce platform specializing in tech products.

YOUR PERSONA:
- Warm, helpful, and professional
- Concise but thorough (under 120 words per response)
- Uses emojis sparingly (1-2 max per response)
- Formats responses with bullet points when listing items

YOUR KNOWLEDGE:
- Products: NexaPro (software tools), NexaHome (smart home devices), NexaWear (wearables)
- Pricing: Free tier, $29/mo Growth, $79/mo Pro, Enterprise custom pricing
- Shipping: 3-5 days standard, 1-2 days express, free shipping over $50
- Support contacts: support@nexashop.com | 1-800-NEXA-BOT | Mon-Fri 9AM-6PM EST
- Returns: 30-day money-back guarantee, free return shipping

YOUR RULES:
- Only discuss NexaShop-related topics
- If asked something off-topic, politely redirect to NexaShop
- Never make up specific prices or details not listed above
- Always offer a next step or call to action
- If you cannot help, escalate to human support`;

  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
      "anthropic-dangerous-direct-browser-access": "true"
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1000,
      system: systemPrompt,
      messages: conversationHistory
    })
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error?.message || `API Error: ${response.status}`);
  }

  const data = await response.json();
  const replyText = data.content[0].text;

  // Add Claude's reply to history for context in future calls
  conversationHistory.push({
    role: "assistant",
    content: replyText
  });

  return replyText;
}


/* ================================================
   PART 7: MAIN MESSAGE PIPELINE

   THIS IS THE CORE FLOW:
   ┌────────────────────────────────────────────┐
   │  1. Get user input                         │
   │  2. Show user message immediately          │
   │  3. Show typing indicator                  │
   │  4. Try pattern matching (retrieval)       │
   │     → Match found? Show predefined answer  │
   │     → No match + API key? Call Claude AI   │
   │     → No match + demo mode? Show fallback  │
   │  5. Hide typing indicator                  │
   │  6. Show bot response                      │
   └────────────────────────────────────────────┘
================================================ */

async function sendMessage() {
  const input = document.getElementById('user-input');
  const text  = input.value.trim();

  // Guard: Don't send empty messages or while bot is typing
  if (!text || isTyping) return;

  input.value = '';
  messageCount++;

  // Show user's message immediately (instant feedback)
  appendUserMessage(text);
  hideQuickReplies();
  showTypingIndicator();
  setInputDisabled(true);

  try {
    // --- STEP 1: Try retrieval-based matching first ---
    const match = matchPattern(text);

    if (match) {
      // Simulate brief "thinking" delay for natural feel
      await sleep(500 + Math.random() * 400);
      hideTypingIndicator();
      appendBotMessage(match.response, match.chips);

    // --- STEP 2: Fall back to Claude AI (generative) ---
    } else if (apiKey && !isDemoMode) {
      const aiReply = await callClaudeAPI(text);
      hideTypingIndicator();
      appendBotMessage(aiReply, ["Ask something else", "View Products", "Talk to Human"]);

    // --- STEP 3: Demo mode fallback ---
    } else {
      await sleep(700);
      hideTypingIndicator();
      appendBotMessage(
        "🤖 I'm in **Demo Mode** and this question is outside my predefined knowledge.\n\nFor full AI responses, please reload the page and enter your Anthropic API key.\n\nMeanwhile, try asking about: **products, pricing, orders, support, or business hours!**",
        ["What products do you offer?", "What are your pricing plans?"]
      );
    }

  } catch (error) {
    console.error('NexaBot Error:', error);
    hideTypingIndicator();

    // User-friendly error messages based on error type
    let errorMsg = "⚠️ Something went wrong. Please try again.";
    if (error.message.includes('401') || error.message.includes('authentication')) {
      errorMsg = "🔑 **API key error** — Your key may be invalid or expired. Please reload and try again.";
    } else if (error.message.includes('429')) {
      errorMsg = "⏱️ **Rate limit reached** — Too many requests. Please wait a moment and try again.";
    } else if (error.message.includes('Failed to fetch')) {
      errorMsg = "🌐 **Connection error** — Please check your internet connection and try again.";
    }

    appendBotMessage(errorMsg, ["Try Again", "Use Demo Mode"]);
  } finally {
    setInputDisabled(false);
    document.getElementById('user-input').focus();
  }
}


/* ================================================
   PART 8: DOM RENDERING FUNCTIONS

   WHY SEPARATE RENDERING FROM LOGIC?
   Separation of concerns — this is a core software
   engineering principle. Logic functions (above)
   decide WHAT to show. Rendering functions (below)
   decide HOW to show it. Makes code easier to
   maintain, test, and update.
================================================ */

function appendUserMessage(text) {
  const messagesEl = document.getElementById('messages');
  const time = getCurrentTime();

  const msgEl = document.createElement('div');
  msgEl.className = 'msg user';
  msgEl.innerHTML = `
    <div class="msg-content">
      <div class="msg-bubble">${escapeHtml(text)}</div>
      <div class="msg-time">${time}</div>
    </div>
    <div class="msg-avatar">👤</div>
  `;

  messagesEl.appendChild(msgEl);
  scrollToBottom();
}

function appendBotMessage(markdownText, chips = []) {
  const messagesEl = document.getElementById('messages');
  const time = getCurrentTime();

  // Convert markdown-like formatting to HTML
  const formattedText = formatBotMessage(markdownText);

  const msgEl = document.createElement('div');
  msgEl.className = 'msg bot';
  msgEl.innerHTML = `
    <div class="msg-avatar">🤖</div>
    <div class="msg-content">
      <div class="msg-bubble">${formattedText}</div>
      <div class="msg-time">${time}</div>
    </div>
  `;

  messagesEl.appendChild(msgEl);

  // Append inline quick reply chips after the message
  if (chips && chips.length > 0) {
    const chipsEl = document.createElement('div');
    chipsEl.className = 'quick-replies';
    chipsEl.style.paddingTop = '0';

    chips.forEach(chipText => {
      const chipEl = document.createElement('span');
      chipEl.className = 'chip';
      chipEl.textContent = chipText;
      chipEl.onclick = () => sendQuick(chipText);
      chipsEl.appendChild(chipEl);
    });

    messagesEl.appendChild(chipsEl);
  }

  scrollToBottom();
}

// Formats the bot's text: **bold**, line breaks, numbered lists
function formatBotMessage(text) {
  return text
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')  // **bold**
    .replace(/\n→ /g, '<br/>→ ')                        // arrow lists
    .replace(/\n• /g, '<br/>• ')                        // bullet lists
    .replace(/\n(\d+)[️⃣]? /g, '<br/>$1. ')             // numbered lists
    .replace(/\n/g, '<br/>');                           // plain newlines
}

// Escapes HTML in user input to prevent XSS attacks
// WHY: If a user types <script>alert('hack')</script>,
// without escaping it would actually run as code!
function escapeHtml(text) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(text));
  return div.innerHTML;
}

function showTypingIndicator() {
  isTyping = true;
  const messagesEl = document.getElementById('messages');

  const typingEl = document.createElement('div');
  typingEl.className = 'msg bot';
  typingEl.id = 'typing-indicator';
  typingEl.innerHTML = `
    <div class="msg-avatar">🤖</div>
    <div class="msg-content">
      <div class="msg-bubble" style="padding: 14px 16px;">
        <div class="typing-indicator">
          <span></span><span></span><span></span>
        </div>
      </div>
    </div>
  `;

  messagesEl.appendChild(typingEl);
  scrollToBottom();
}

function hideTypingIndicator() {
  isTyping = false;
  const el = document.getElementById('typing-indicator');
  if (el) el.remove();
}

function hideQuickReplies() {
  // Hide the top-level quick reply chips after user starts chatting
  const chips = document.getElementById('quick-replies');
  if (chips) chips.style.display = 'none';
}

function setInputDisabled(state) {
  document.getElementById('user-input').disabled = state;
  document.getElementById('send-btn').disabled   = state;
}

function scrollToBottom() {
  const msgs = document.getElementById('messages');
  msgs.scrollTop = msgs.scrollHeight;
}

function getCurrentTime() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


/* ================================================
   PART 9: WIDGET CONTROLS
================================================ */

function toggleChat() {
  chatOpen = !chatOpen;
  const panel  = document.getElementById('chat-panel');
  const icon   = document.getElementById('toggle-icon');

  panel.classList.toggle('open', chatOpen);
  icon.textContent = chatOpen ? '✕' : '💬';

  if (chatOpen) {
    // Focus the input when chat opens
    setTimeout(() => {
      document.getElementById('user-input').focus();
    }, 300);
  }
}

function openChat() {
  if (!chatOpen) toggleChat();
}

function clearChat() {
  document.getElementById('messages').innerHTML = '';
  conversationHistory = [];
  messageCount = 0;
  document.getElementById('quick-replies').style.display = 'flex';
  // Re-show welcome message after clearing
  initChat(isDemoMode);
}

function sendQuick(text) {
  const input = document.getElementById('user-input');
  input.value = text;
  sendMessage();
}

function handleKey(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
}


/* ================================================
   PART 10: AUTO-INITIALIZATION ON PAGE LOAD

   WHY CHECK sessionStorage ON LOAD?
   If the user refreshes the page mid-conversation,
   we can restore their API key automatically so
   they don't have to re-enter it each time.
   Session still ends when the tab closes.
================================================ */

window.addEventListener('DOMContentLoaded', () => {
  // Check if API key was already entered this session
  const savedKey = sessionStorage.getItem('nexabot_key');

  if (savedKey) {
    apiKey = savedKey;
    // Hide modal since key already exists
    const modal = document.getElementById('api-modal');
    modal.style.display = 'none';
    initChat(false);
  }

  // Keyboard shortcut: Press '/' to focus chat input when panel is open
  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && chatOpen && document.activeElement !== document.getElementById('user-input')) {
      e.preventDefault();
      document.getElementById('user-input').focus();
    }
  });
});