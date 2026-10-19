const express = require("express");

const router = express.Router();

router.post("/", (req, res) => {
  const { url: submittedUrl } = req.body || {};

  if (typeof submittedUrl !== "string" || submittedUrl.trim() === "") {
    return res.status(400).json({ error: "A URL is required." });
  }

  let url;
  try {
    url = new URL(submittedUrl);
  } catch {
    return res.status(400).json({ error: "The URL is malformed." });
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return res.status(400).json({ error: "Only HTTP and HTTPS URLs are supported." });
  }

  return res.json({
    status: "not_yet_investigated",
    summary: "This is a demo response. No real security investigation has been performed.",
    evidence: [],
    domain: url.hostname
  });
});

module.exports = router;
