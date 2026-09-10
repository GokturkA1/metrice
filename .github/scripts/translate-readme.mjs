import fs from 'node:fs';
import path from 'node:path';

const apiKey = process.env.GEMINI_API_KEY;

if (!apiKey) {
  console.log('Notice: GEMINI_API_KEY secret is not configured in repository.');
  console.log('To enable automated AI translation, add GEMINI_API_KEY to GitHub Secrets.');
  console.log('Free keys can be generated at https://aistudio.google.com/app/apikey');
  process.exit(0);
}

const rootDir = path.resolve(import.meta.dirname, '../..');
const trPath = path.join(rootDir, 'README.tr.md');
const enPath = path.join(rootDir, 'README.md');

if (!fs.existsSync(trPath)) {
  console.error('Error: README.tr.md not found.');
  process.exit(1);
}

const trContent = fs.readFileSync(trPath, 'utf8');

console.log('Translating README.tr.md to English using Gemini API...');

const prompt = `You are a world-class systems software engineer and technical translator specializing in cryptography, P2P networks, and decentralized protocols.

Translate the following Turkish technical README for "Metrice" into professional, fluent, idiomatic English.

STRICT TRANSLATION RULES:
1. Preserve all Markdown structure, headings, bullet points, tables, and fenced code blocks exactly intact.
2. Do NOT alter or translate code snippets, command line flags, environment variable names, port numbers, or JSON payloads.
3. Cryptographic & P2P Networking terminology translation requirements:
   - "kuantum sonrası kriptografi" -> "Post-Quantum Cryptography"
   - "anahtar kapsülleme" -> "key encapsulation"
   - "soğan yönlendirme" -> "onion routing"
   - "teleskopik soğan devresi" -> "telescopic onion circuit"
   - "ters tünel" -> "reverse tunnel"
   - "varlık senkronizasyonu" -> "presence synchronization"
   - "dedikodu" -> "gossip"
   - "düğüm kimliği" -> "node identity"
   - "yansıtılan IP konsensüsü" -> "reflected IP consensus"
   - "diyal-geri" / "geri bağlantı" -> "dialback"
   - "örgü" -> "mesh"
   - "uç" -> "edge"
   - "röle" -> "relay"
4. Ensure the top navigation bar remains:
   [English](README.md) | [Türkçe](README.tr.md)
5. Output ONLY the raw markdown content. Do NOT wrap your output in a markdown code fence like \`\`\`markdown.

Document to translate:
${trContent}`;

try {
  const candidateModels = ['gemini-3.6-flash', 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
let translated = null;
let lastError = null;

for (const model of candidateModels) {
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{
          parts: [{ text: prompt }]
        }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 8192
        }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      lastError = `Model ${model} returned (${response.status}): ${errText}`;
      console.warn(lastError);
      continue;
    }

    const data = await response.json();
    translated = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (translated && translated.trim().length >= 500) {
      console.log(`Successfully generated translation using ${model}`);
      break;
    }
  } catch (err) {
    lastError = err.message;
    console.warn(`Model ${model} failed: ${err.message}`);
  }
}

if (!translated || translated.trim().length < 500) {
  console.error(`Translation failed across candidate models. Last error: ${lastError}`);
  process.exit(1);
}

  // Remove potential triple backtick wrapper if model wrapped response
  if (translated.startsWith('```markdown\n')) {
    translated = translated.slice(12);
  } else if (translated.startsWith('```\n')) {
    translated = translated.slice(4);
  }
  if (translated.endsWith('```\n')) {
    translated = translated.slice(0, -4);
  } else if (translated.endsWith('```')) {
    translated = translated.slice(0, -3);
  }

  fs.writeFileSync(enPath, translated.trim() + '\n', 'utf8');
  console.log('Successfully translated and updated README.md!');
} catch (err) {
  console.error(`Translation failed: ${err.message}`);
  process.exit(1);
}
