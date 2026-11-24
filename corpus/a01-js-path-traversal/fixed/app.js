const express = require('express');
const path = require('path');
const app = express();
const FILES = path.join(__dirname, 'files');
app.get('/download', (req, res) => {
  res.sendFile(path.basename(String(req.query.name)), { root: FILES });
});
const { readFileSync } = require('node:fs');
const fontNames = ['regular.woff2', 'bold.woff2'];
const fonts = new Map(fontNames.map((font) => [font, readFileSync(new URL(`../static/fonts/${font}`, import.meta.url))]));
app.get('/font/:font', (req, res) => {
  const font = req.params.font;
  res.send(fonts.get(font));
});
