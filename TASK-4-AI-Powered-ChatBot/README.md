# 🤖 NexaBot — AI-Powered Chatbot

# Project Overview 

NexaBot is a fully functional AI-powered chatbot built for a fictional e-commerce platform called NexaShop. It demonstrates how modern businesses embed AI customer support directly into their websites.

## The chatbot uses a hybrid AI architecture:

Retrieval-Based Layer — 
Instantly matches user queries to predefined commercial patterns 
(products, pricing, orders, support, etc.)

Generative AI Layer — 
Falls back to Claude (Anthropic) for any question outside predefined patterns, enabling truly intelligent, contextual conversation


## 🛠️ Tech Stack

| Technology | Purpose | Why Chosen |
|---|---|---|
| **HTML5** | Page structure | Semantic, accessible markup |
| **CSS3** | Styling & animations | Variables, flexbox, keyframes |
| **Vanilla JavaScript** | Chatbot logic | No framework overhead, fast loading |
| **Claude API (Anthropic)** | Generative AI responses | Best-in-class instruction following |
| **Google Fonts** | Typography (Syne + DM Sans) | Professional, modern aesthetic |



# Features ✨ 

| 🤖 AI Architecture                             | 💬 Chat UI/UX                    | 🔒 Security                                |
| ---------------------------------------------- | -------------------------------- | ------------------------------------------ |
| Hybrid chatbot: pattern matching + AI fallback | Floating chat widget             | API key stored in **sessionStorage**       |
| 9 intent categories for user queries           | Smooth animated chat panel       | Clears automatically when tab closes       |
| 60+ trigger keywords for intent detection      | Typing indicator animation       | **XSS protection** using `escapeHtml()`    |
| Chat context sent to **Claude API**            | Quick reply buttons              | API key only sent to **api.anthropic.com** |
|                                                | Message timestamps & auto-scroll |                                            |
|                                                | **/** shortcut to focus input    |                                            |


## Responsive Design📱 

Works on desktop, tablet, and mobile

Mobile: full-width panel, adjusted positioning

## Error Handling🛡️ 

Invalid API key detection

Rate limit (429) detection

Network failure detection

User-friendly error messages for each scenario



# File Tree: TASK-4-AI-Powered-ChatBot


```
├── 📁 NexaBot
│   ├── 📁 Assets
│   │   ├── 📁 css
│   │   │   └── 🎨 style.css
│   │   └── 📁 js
│   │       └── 📄 chatbot.js
│   ├── 📁 Docs
│   │   └── 📁 screenshots
│   └── 🌐 index.html
└── 📝 README.md
```

