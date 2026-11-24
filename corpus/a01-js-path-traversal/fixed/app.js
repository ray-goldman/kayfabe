import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
const app = express();
const FILES = fileURLToPath(new URL('./files/', import.meta.url));
app.get('/download', (req, res) => {
  res.sendFile(path.basename(String(req.query.name)), { root: FILES });
});
const fontNames = ['regular.woff2', 'bold.woff2'];
const fonts = new Map(fontNames.map((font) => [font, readFileSync(new URL(`../static/fonts/${font}`, import.meta.url))]));
app.get('/font/:font', (req, res) => {
  const font = req.params.font;
  res.send(fonts.get(font));
});
