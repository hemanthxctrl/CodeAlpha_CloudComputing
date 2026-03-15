# 🤖 NexaBot — AI-Powered Chatbot

# Project Overview 

NexaBot is a fully functional AI-powered chatbot built for a fictional e-commerce platform called NexaShop. 

It demonstrates how modern businesses embed AI customer support directly into their websites.

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

# Architecture Diagram
![Arc. Diagram](/TASK-4-AI-Powered-ChatBot/Downloads/wallpapers/architecture.pngREADME.md)


# How to Run

## Method  1: GitHub Pages (Recommended for submission)

Push this repo to GitHub
Go to Settings → Pages → Source: main branch
Your chatbot will be live at https://yourusername.github.io/nexabot/

## Method 2: Run Locally

1)first Clone the repository
git clone https://github.com/YOUR_USERNAME/nexabot.git
2)Navigate into the folder
cd nexabot
3)Open in browser (no server needed — pure HTML/CSS/JS)
4)open index.html          # macOS
5)start index.html         # Windows
6)xdg-open index.html      # Linux

## Method 3: VS Code Live Server

Install the Live Server extension in VS Code
Right-click index.html → Open with Live Server

## To Get Your API Key

Visit console.anthropic.com
Sign up / Log in
Go to API Keys → Create Key
Copy the key (starts with sk-ant-)
Paste it into the chatbot when prompted


💡 Don't have an API key? Use Demo Mode to test all predefined responses without any key.

# Test Cases

| 🧪 User Input                                         | Expected Response Type       | Category       |
| ----------------------------------------------------- | ---------------------------- | -------------- |
| "hello"                                               | Predefined (instant)         | Greeting       |
| "what products do you sell?"                          | Predefined (instant)         | Products       |
| "how much does it cost?"                              | Predefined (instant)         | Pricing        |
| "where is my order?"                                  | Predefined (instant)         | Order Tracking |
| "I have a bug"                                        | Predefined (instant)         | Support        |
| "what are your hours?"                                | Predefined (instant)         | Business Hours |
| "I want a refund"                                     | Predefined (instant)         | Returns        |
| "I forgot my password"                                | Predefined (instant)         | Account        |
| "what's the difference between NexaPro and NexaWear?" | Claude AI (generative)       | Complex Query  |
| "can you recommend a product for a small apartment?"  | Claude AI (generative)       | Complex Query  |
| Any off-topic question                                | Claude AI redirects politely | Guardrails     |


# Developed by:

- Hemanth Sreenivas
- CodeAlpha Virtual Internship
- Cloud Computing
- Task-4-AI-Powered-ChatBot

---

*Built and deployed on AWS as part of CodeAlpha Cloud Computing Virtual Internship*
