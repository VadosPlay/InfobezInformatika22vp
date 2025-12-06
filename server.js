const express = require("express");
const path = require("path");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Разрешаем запросы с фронтенда
app.use(cors());
app.use(express.json());

// Отдаём все статические файлы (index.html, script.js, style.css)
app.use(express.static(__dirname));

// Чтобы точно отдать index.html при заходе на /
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Endpoint для VirusTotal (пример)
app.post("/vt/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL отсутствует" });

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "API ключ не настроен" });

    const fetch = require("node-fetch");
    const vtResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`
    });

    const json = await vtResponse.json();
    const scanId = json.data.id;

    const reportResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
      headers: { "x-apikey": apiKey }
    });

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

// Запуск сервера
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
