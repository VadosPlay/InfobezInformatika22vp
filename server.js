const express = require("express");
const fetch = require("node-fetch");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // отдаёт index.html, script.js, style.css и др.

// Чтобы точно отдать index.html при GET /
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Endpoint для VirusTotal
app.post("/vt/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL отсутствует" });

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "API ключ не настроен" });

    const vtResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const json = await vtResponse.json();
    const scanId = json.data.id;

    const reportResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${scanId}`,
      { headers: { "x-apikey": apiKey } }
    );

    const reportJson = await reportResponse.json();
    const stats = reportJson.data.attributes.stats;

    res.json({
      harmless: stats.harmless,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      undetected: stats.undetected
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка проверки" });
  }
});

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
