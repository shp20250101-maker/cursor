import { verseForDate, storageKeyForDate } from "./verses.js";

const today = new Date();
const reading = verseForDate(today);
const journalKey = storageKeyForDate(today);

const dateEl = document.getElementById("hero-date");
const verseTextEl = document.getElementById("verse-text");
const verseRefEl = document.getElementById("verse-ref");
const promptEl = document.getElementById("meditate-prompt");
const journalEl = document.getElementById("journal-note");
const journalHintEl = document.getElementById("journal-hint");
const timerDisplay = document.getElementById("timer-display");
const timerToggle = document.getElementById("timer-toggle");
const timerReset = document.getElementById("timer-reset");
const presets = document.querySelectorAll(".preset");

dateEl.textContent = today.toLocaleDateString(undefined, {
  weekday: "long",
  month: "long",
  day: "numeric",
});

verseTextEl.textContent = `“${reading.text}”`;
verseRefEl.textContent = reading.ref;
promptEl.textContent = reading.prompt;

const savedNote = localStorage.getItem(journalKey);
if (savedNote) {
  journalEl.value = savedNote;
  journalHintEl.textContent = "Saved on this device.";
}

let saveTimer;
journalEl.addEventListener("input", () => {
  clearTimeout(saveTimer);
  journalHintEl.textContent = "Saving…";
  saveTimer = setTimeout(() => {
    localStorage.setItem(journalKey, journalEl.value);
    journalHintEl.textContent = "Saved on this device.";
  }, 350);
});

let durationSeconds = 300;
let remainingSeconds = durationSeconds;
let intervalId = null;
let running = false;

function formatTime(total) {
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

function renderTimer() {
  timerDisplay.textContent = formatTime(remainingSeconds);
  timerToggle.textContent = running ? "Pause" : remainingSeconds === durationSeconds ? "Start" : "Resume";
}

function stopTimer(reset = false) {
  clearInterval(intervalId);
  intervalId = null;
  running = false;
  if (reset) remainingSeconds = durationSeconds;
  renderTimer();
}

function startTimer() {
  if (remainingSeconds <= 0) remainingSeconds = durationSeconds;
  running = true;
  renderTimer();
  intervalId = setInterval(() => {
    remainingSeconds -= 1;
    if (remainingSeconds <= 0) {
      remainingSeconds = 0;
      stopTimer();
      timerDisplay.classList.add("timer-done");
      setTimeout(() => timerDisplay.classList.remove("timer-done"), 1200);
      return;
    }
    renderTimer();
  }, 1000);
}

timerToggle.addEventListener("click", () => {
  if (running) stopTimer();
  else startTimer();
});

timerReset.addEventListener("click", () => stopTimer(true));

presets.forEach((btn) => {
  btn.addEventListener("click", () => {
    presets.forEach((p) => p.classList.remove("is-active"));
    btn.classList.add("is-active");
    durationSeconds = Number(btn.dataset.seconds);
    stopTimer(true);
  });
});

renderTimer();

const revealEls = document.querySelectorAll(".section, .verse-block, .meditate-layout > *");
const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    });
  },
  { threshold: 0.15 }
);
revealEls.forEach((el) => {
  el.classList.add("reveal");
  observer.observe(el);
});
