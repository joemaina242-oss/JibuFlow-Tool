const OpenAI = require("openai");
const memory = require("./memory");
require("dotenv").config();

const client = new OpenAI({
  apiKey: process.env.GROQ_API_KEY,
  baseURL: "https://api.groq.com/openai/v1",
});

function buildSystemPrompt(brandContext) {
  const whatsapp = process.env.WHATSAPP_NUMBER || "[Your WhatsApp Number]";
  return `You are JibuFlow (One Brain) — an AI sales assistant handling TikTok comment replies for a business.

BRAND CONTEXT:
${brandContext}

CRITICAL GUARDRAILS — NEVER BREAK THESE

1. TWO-CHANNEL REPLY SYSTEM
   You generate TWO separate messages for every medium/high intent comment:

   A) PUBLIC COMMENT REPLY (the "reply" field):
      - NEVER include a phone number, WhatsApp link, or any contact detail here.
      - Instead tease the DM. Examples:
        "Sasa @[username]! Check your DMs — tumekutumia details zote"
        "Hey @[username]! Tumekutumia inbox yako all details + availability. Check it out!"
      - Keep it warm, human, under 180 characters.
      - This keeps your comments clean and avoids TikTok spam flags.

   B) PRIVATE DM MESSAGE (the "dm_message" field):
      - This is the full private message sent to the customer's inbox.
      - Include the WhatsApp number here: ${whatsapp}
      - Include specific product details, price (if known from brand context), and a CTA.
      - Can be up to 400 characters. More personal, more detailed.

2. NEVER GUESS PRICES
   ONLY quote prices explicitly listed in the brand context above.
   If price is unknown -> in the DM, say "WhatsApp us on ${whatsapp} for exact pricing."
   NEVER estimate or invent a number.

3. NEVER PROMISE CALLBACKS
   Never say "our team will call you" or "expect a call."
   Always redirect to WhatsApp: ${whatsapp}

4. NEVER MAKE PROMISES YOU CAN'T KEEP
   No delivery date promises unless in brand context.
   No stock guarantees unless in brand context.

5. LANGUAGE MATCHING
   Match the language of the comment — Sheng, Swahili, or English.
   Sound human. Never robotic or corporate.`;
}

function buildUserPrompt({ username, comment, memoryBlock }) {
  return `Customer username: ${username}
Known memory about this customer:
${memoryBlock}

Incoming TikTok comment: "${comment}"

Your job:
Score INTENT as: low, medium, or high
  low    = emoji reactions, generic hype, no buying signal
  medium = asking for info (price, part, availability, location)
  high   = strong buying signal (urgency, specific item, ready to order)

If LOW -> do NOT reply. Explain why to skip.
If MEDIUM or HIGH -> generate BOTH messages following ALL guardrails:
  "reply"      -> short public comment (no contact info, teases the DM)
  "dm_message" -> full private DM (includes WhatsApp number + details)

Extract any NEW facts worth remembering from this comment.

Respond ONLY in this JSON format — no markdown, no text outside the JSON:
{
  "intent": "low" | "medium" | "high",
  "intent_reason": "one sentence why",
  "should_reply": true | false,
  "reply": "short public comment reply or null if low intent",
  "dm_message": "full private DM message or null if low intent",
  "memory_used": ["list of fact keys referenced"],
  "new_facts": [{"key": "snake_case_key", "value": "value", "confidence": 0-100}],
  "skip_reason": "why we skip — only if low intent"
}`;
}

function safeParse(raw) {
  const clean = String(raw || "").replace(/```json|```/g, "").trim();
  try { return JSON.parse(clean); } catch (_) {}
  const m = clean.match(/\{[\s\S]*\}/);
  if (m) { try { return JSON.parse(m[0]); } catch (_) {} }
  return {
    intent: "low", intent_reason: "unparseable model output",
    should_reply: false, reply: null, dm_message: null,
    memory_used: [], new_facts: [], skip_reason: "model output could not be parsed",
  };
}

async function processComment({ username, comment, brandContext, meta }) {
  console.log(`\n🧠 Processing comment from ${username}: "${comment}"`);
  const userMemory = await memory.getMemory(username);
  const memoryBlock = userMemory.length > 0
    ? userMemory.map((f) => `- ${f.fact_key}: ${f.fact_value}`).join("\n")
    : "No prior memory for this user.";

  const response = await client.chat.completions.create({
    model: "llama-3.3-70b-versatile",
    max_tokens: 1000,
    messages: [
      { role: "system", content: buildSystemPrompt(brandContext) },
      { role: "user", content: buildUserPrompt({ username, comment, memoryBlock }) },
    ],
  });
  const result = safeParse(response.choices[0].message.content);

  console.log(`Intent: ${String(result.intent).toUpperCase()} — ${result.intent_reason}`);
  if (result.should_reply) {
    console.log(`Public reply: ${result.reply}`);
    console.log(`DM message: ${result.dm_message}`);
  } else {
    console.log(`>> Skipped: ${result.skip_reason}`);
  }

  if (result.new_facts && result.new_facts.length > 0) {
    for (const fact of result.new_facts) {
      if (fact.confidence >= 75) {
        await memory.saveFact(username, fact.key, fact.value, fact.confidence);
        console.log(`Saved: ${fact.key} = ${fact.value}`);
      }
    }
  }

  await memory.logInteraction(username, comment, result.reply, result.intent, meta || {});
  return result;
}

module.exports = { processComment };