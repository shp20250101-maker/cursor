# Abide

A quiet, web-based daily Bible reading site for reading and meditation.

Each calendar day shows one curated scripture, a short meditation prompt, an optional quiet timer, and a private journal note saved only in your browser.

## Run locally

```bash
cd abide
npm install
npm run dev
```

Open the URL Vite prints (default `http://localhost:5173`).

## Build

```bash
cd abide
npm run build
npm run preview
```

## How the daily verse works

Verses are selected by day-of-year from a curated list in `src/verses.js`, so everyone sees the same reading on a given local date. Journal notes are keyed by date in `localStorage` and never leave the device.
