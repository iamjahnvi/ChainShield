const path = require("path");

require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

const express = require("express");
const investigationsRouter = require("./routes/investigations");

const app = express();

app.use((req, res, next) => {
  const origin = req.get("Origin");
  const isChromeExtensionOrigin =
    typeof origin === "string" &&
    /^chrome-extension:\/\//i.test(origin);

  // Unpacked extension IDs vary by installation. Allow Chrome extension origins,
  // but do not grant cross-origin access to arbitrary websites.
  if (isChromeExtensionOrigin) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Vary", "Origin");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(isChromeExtensionOrigin ? 204 : 403);
  }

  next();
});

app.use(express.json({ limit: "10kb" }));

app.get("/", (req, res) => {
  res.json({
    name: "ChainShield API",
    status: "ok",
    endpoints: {
      health: "/api/health",
      investigations: "POST /api/investigations"
    }
  });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use("/api/investigations", investigationsRouter);

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && "body" in err) {
    return res.status(400).json({ error: "Request body must be valid JSON." });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body is too large." });
  }

  return next(err);
});

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;

  const apiKey = process.env.TINYFISH_API_KEY;
  if (typeof apiKey !== "string" || apiKey.trim() === "") {
    console.error(
      "ChainShield configuration warning: TINYFISH_API_KEY is not set. " +
        "Add it to server/.env; investigation requests will fail with a configuration error until it is set."
    );
  }

  app.listen(port, () => {
    console.log(`ChainShield demo API listening at http://localhost:${port}`);
  });
}

module.exports = app;
