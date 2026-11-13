// Speech-to-text without a trained model: template matching on spectrograms.
//
// 1. Turn the input waveform into a spectrogram (FFT of short frames).
// 2. Squash it into MFCCs, which describe the shape of the sound and ignore
//    most of the voice's pitch and loudness.
// 3. Do the same for reference recordings of every word we know.
// 4. Compare the input against each reference with dynamic time warping
//    (DTW), which lines up two recordings spoken at different speeds.
// 5. The word whose reference is closest wins.
//
// Without a trained model, the recognizer can only choose between words it
// has reference recordings for. Those words are listed in words.txt, one per
// line. Any word added there is recorded automatically on the next run with
// the macOS `say` command, in several voices, and saved in ./templates.
// A word that is not in words.txt comes out as the closest word that is.
//
// Usage: node index.js [file.wav] [--no-play]

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const wav = require("node-wav");
const { fft } = require("fft-js");
const { resample } = require("wave-resampler");
const player = require("play-sound")();

// Words the recognizer knows: one per line in words.txt.
const WORDS_FILE = path.join(__dirname, "words.txt");

function loadVocabulary() {
    const words = fs.readFileSync(WORDS_FILE, "utf8")
        .split(/\r?\n/)
        .map((line) => line.trim().toLowerCase())
        .filter((line) => line && !line.startsWith("#"));

    for (const word of words) {
        if (!/^[a-z]+$/.test(word)) {
            throw new Error(`words.txt: "${word}" must be a single word using letters a-z only`);
        }
    }

    return [...new Set(words)];
}

// Voices for the reference recordings. More voices = more robust matching.
const VOICES = ["Samantha", "Daniel", "Karen", "Moira", "Rishi", "Tessa", "Fred"];

const TEMPLATE_DIR = path.join(__dirname, "templates");

// Signal settings.
const SAMPLE_RATE = 16000;
const FRAME_SIZE = 512;      // 32 ms per frame (FFT size must be a power of 2)
const HOP_SIZE = 160;        // a new frame every 10 ms
const MEL_BANDS = 26;        // frequency bands, spaced like human hearing
const MFCC_COUNT = 13;       // coefficients kept per frame
const SILENCE_DB = 35;       // frames this far below the loudest are silence
const LENGTH_PENALTY = 0.5;  // how much a length mismatch counts against a match

// ---------------------------------------------------------------------------
// Audio
// ---------------------------------------------------------------------------

// node-wav mis-reads a Buffer that starts partway into Node's shared memory
// pool (it stops before reaching the audio). Give it a standalone copy.
function readWav(filePath) {
    const buffer = fs.readFileSync(filePath);
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.length);
}

function loadAudio(filePath) {
    const decoded = wav.decode(readWav(filePath));

    // Mix all channels down to mono.
    const channels = decoded.channelData;
    let waveform = new Float32Array(channels[0].length);

    for (const channel of channels) {
        for (let i = 0; i < waveform.length; i++) {
            waveform[i] += channel[i] / channels.length;
        }
    }

    // Use one sample rate for everything, so spectrogram bins line up.
    if (decoded.sampleRate !== SAMPLE_RATE) {
        waveform = Float32Array.from(
            resample(waveform, decoded.sampleRate, SAMPLE_RATE, { method: "sinc" })
        );
    }

    return { waveform, originalRate: decoded.sampleRate };
}

// ---------------------------------------------------------------------------
// Spectrogram
// ---------------------------------------------------------------------------

// Hann window: fades each frame in and out so its edges don't add fake
// frequencies to the FFT.
const HANN = Float32Array.from({ length: FRAME_SIZE }, (_, n) =>
    0.5 - 0.5 * Math.cos((2 * Math.PI * n) / (FRAME_SIZE - 1))
);

// Power spectrogram: one row per 10 ms frame, one column per frequency bin
// (0 Hz up to 8000 Hz in 31.25 Hz steps).
function computeSpectrogram(waveform) {
    // Pre-emphasis boosts high frequencies, where consonants live.
    const emphasized = new Float32Array(waveform.length);
    emphasized[0] = waveform[0];

    for (let i = 1; i < waveform.length; i++) {
        emphasized[i] = waveform[i] - 0.97 * waveform[i - 1];
    }

    const spectrogram = [];
    const frame = new Array(FRAME_SIZE);

    for (let start = 0; start + FRAME_SIZE <= emphasized.length; start += HOP_SIZE) {
        for (let n = 0; n < FRAME_SIZE; n++) {
            frame[n] = emphasized[start + n] * HANN[n];
        }

        const phasors = fft(frame);
        const power = new Float32Array(FRAME_SIZE / 2 + 1);

        for (let k = 0; k < power.length; k++) {
            const [re, im] = phasors[k];
            power[k] = (re * re + im * im) / FRAME_SIZE;
        }

        spectrogram.push(power);
    }

    return spectrogram;
}

// ---------------------------------------------------------------------------
// Spectrogram -> MFCC features
// ---------------------------------------------------------------------------

const hzToMel = (hz) => 2595 * Math.log10(1 + hz / 700);
const melToHz = (mel) => 700 * (10 ** (mel / 2595) - 1);

// Triangular filters, evenly spaced on the mel scale between 80 and 7600 Hz.
// Each one sums a band of FFT bins into one "how loud is this band" number.
function createMelFilters() {
    const bins = FRAME_SIZE / 2 + 1;
    const low = hzToMel(80);
    const high = hzToMel(7600);

    const edges = Array.from({ length: MEL_BANDS + 2 }, (_, i) =>
        Math.floor(((FRAME_SIZE + 1) * melToHz(low + ((high - low) * i) / (MEL_BANDS + 1))) / SAMPLE_RATE)
    );

    return Array.from({ length: MEL_BANDS }, (_, m) => {
        const filter = new Float32Array(bins);
        const [left, center, right] = [edges[m], edges[m + 1], edges[m + 2]];

        for (let k = left; k < center; k++) filter[k] = (k - left) / (center - left);
        for (let k = center; k < right; k++) filter[k] = (right - k) / (right - center);

        return filter;
    });
}

const MEL_FILTERS = createMelFilters();

// Log energy in each mel band, per frame.
function melSpectrogram(spectrogram) {
    return spectrogram.map((power) =>
        MEL_FILTERS.map((filter) => {
            let energy = 0;
            for (let k = 0; k < power.length; k++) energy += filter[k] * power[k];
            return Math.log(energy + 1e-10);
        })
    );
}

// Keep only the frames between the first and last loud one.
function trimSilence(melFrames) {
    const loudness = melFrames.map((bands) => Math.max(...bands));
    const threshold = Math.max(...loudness) - SILENCE_DB / (10 / Math.LN10);

    const first = loudness.findIndex((value) => value > threshold);
    const last = loudness.length - 1 - [...loudness].reverse().findIndex((value) => value > threshold);

    return melFrames.slice(first, last + 1);
}

// DCT of each frame's mel energies -> MFCCs. Coefficient 0 (overall
// loudness) is dropped, and each coefficient's average over the word is
// subtracted, so the same word at a different volume or through a different
// microphone still looks the same.
function mfcc(melFrames) {
    const coefficients = melFrames.map((bands) =>
        Array.from({ length: MFCC_COUNT - 1 }, (_, i) => {
            const c = i + 1;
            let sum = 0;
            for (let m = 0; m < MEL_BANDS; m++) {
                sum += bands[m] * Math.cos((Math.PI * c * (m + 0.5)) / MEL_BANDS);
            }
            return sum;
        })
    );

    const mean = coefficients[0].map((_, i) =>
        coefficients.reduce((total, frame) => total + frame[i], 0) / coefficients.length
    );

    return coefficients.map((frame) => frame.map((value, i) => value - mean[i]));
}

function features(waveform) {
    const melFrames = trimSilence(melSpectrogram(computeSpectrogram(waveform)));
    return { melFrames, mfccs: mfcc(melFrames) };
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

function frameDistance(a, b) {
    let sum = 0;
    for (let i = 0; i < a.length; i++) sum += (a[i] - b[i]) ** 2;
    return Math.sqrt(sum);
}

// Dynamic time warping: the cheapest way to line up two sequences of frames,
// allowing either one to stretch or shrink in time. Returns the average
// distance per step of that best alignment.
function dtw(a, b) {
    const n = a.length;
    const m = b.length;

    let previous = new Float64Array(m + 1).fill(Infinity);
    previous[0] = 0;

    // steps[j] = how many steps the best path to this cell took.
    let previousSteps = new Float64Array(m + 1);

    for (let i = 1; i <= n; i++) {
        const current = new Float64Array(m + 1).fill(Infinity);
        const currentSteps = new Float64Array(m + 1);

        for (let j = 1; j <= m; j++) {
            const cost = frameDistance(a[i - 1], b[j - 1]);

            const options = [
                [previous[j - 1], previousSteps[j - 1]],   // both advance
                [previous[j], previousSteps[j]],           // a advances
                [current[j - 1], currentSteps[j - 1]]      // b advances
            ];

            const [best, steps] = options.reduce((x, y) => (y[0] < x[0] ? y : x));

            current[j] = best + cost;
            currentSteps[j] = steps + 1;
        }

        previous = current;
        previousSteps = currentSteps;
    }

    return previous[m] / previousSteps[m];
}

// ---------------------------------------------------------------------------
// Reference recordings
// ---------------------------------------------------------------------------

function templatePath(word, voice) {
    return path.join(TEMPLATE_DIR, `${word}-${voice}.wav`);
}

// Record any missing reference words with the macOS speech synthesizer.
function ensureTemplates(vocabulary) {
    fs.mkdirSync(TEMPLATE_DIR, { recursive: true });

    const missing = vocabulary.flatMap((word) => VOICES.map((voice) => ({ word, voice })))
        .filter(({ word, voice }) => !fs.existsSync(templatePath(word, voice)));

    if (missing.length === 0) return;

    console.log(`Recording ${missing.length} reference words with the macOS "say" command...`);

    for (const { word, voice } of missing) {
        execFileSync("say", [
            "-v", voice,
            "-o", templatePath(word, voice),
            "--file-format=WAVE",
            "--data-format=LEI16@16000",
            word
        ]);
    }
}

// Every WAV file in ./templates named "<word>-<voice>.wav" is a reference,
// for words listed in words.txt. You can add your own recordings the same
// way (e.g. "usman-me.wav"); recordings of your own voice match it best.
function loadTemplates(vocabulary) {
    return fs.readdirSync(TEMPLATE_DIR)
        .filter((file) => /^[a-z]+-.+\.wav$/i.test(file))
        .map((file) => {
            const [word, ...rest] = path.basename(file, ".wav").split("-");
            return { file, word: word.toLowerCase(), voice: rest.join("-") };
        })
        .filter(({ word }) => vocabulary.includes(word))
        .sort((a, b) => a.file.localeCompare(b.file))
        .map(({ file, word, voice }) => ({
            word,
            voice,
            mfccs: features(loadAudio(path.join(TEMPLATE_DIR, file)).waveform).mfccs
        }));
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

// Draw the mel spectrogram in the terminal: low frequencies at the bottom,
// time left to right, brighter characters = louder.
function printSpectrogram(melFrames, width = 64) {
    const shades = " .:-=+*#%@";
    const all = melFrames.flat();
    const max = Math.max(...all);
    const min = max - 60 / (10 / Math.LN10);   // show a 60 dB range

    const columns = Math.min(width, melFrames.length);

    for (let band = MEL_BANDS - 1; band >= 0; band--) {
        let row = "";

        for (let c = 0; c < columns; c++) {
            const frame = melFrames[Math.floor((c * melFrames.length) / columns)];
            const level = Math.min(1, Math.max(0, (frame[band] - min) / (max - min)));
            row += shades[Math.round(level * (shades.length - 1))];
        }

        const label = band === MEL_BANDS - 1 ? "7.6 kHz" : band === 0 ? "  80 Hz" : "       ";
        console.log(`  ${label} |${row}|`);
    }

    console.log(`          ${"-".repeat(columns + 2)}`);
    console.log(`           0 ms${" ".repeat(Math.max(1, columns - 12))}${melFrames.length * 10} ms`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

// Play the audio file through the speakers. Resolves when playback ends;
// a playback problem is reported but does not stop the recognition.
function playAudio(file) {
    return new Promise((resolve) => {
        player.play(file, (error) => {
            if (error) console.error(`\n(Could not play the audio: ${error.message || error})`);
            resolve();
        });
    });
}

async function main() {
    const args = process.argv.slice(2);
    const file = path.resolve(args.find((arg) => !arg.startsWith("--")) || path.join(__dirname, "./templates/usman-Samantha.wav"));

    // Start playing while the recognizer works.
    const playback = args.includes("--no-play") ? Promise.resolve() : playAudio(file);

    const vocabulary = loadVocabulary();

    ensureTemplates(vocabulary);

    const { waveform, originalRate } = loadAudio(file);
    const input = features(waveform);

    console.log(`\nInput: ${path.basename(file)} (${originalRate} Hz, ${(waveform.length / SAMPLE_RATE).toFixed(2)} s)`);
    console.log(`Speech found: ${input.melFrames.length * 10} ms after trimming silence\n`);
    console.log("Mel spectrogram:");
    printSpectrogram(input.melFrames);

    // Compare the input with every reference recording.
    const templates = loadTemplates(vocabulary);
    const perWord = new Map();

    for (const template of templates) {
        // DTW can stretch a short word over a long one (e.g. "up" over
        // "usman") at little cost, so also penalize very different lengths.
        const lengthRatio = Math.abs(Math.log(input.mfccs.length / template.mfccs.length));
        const distance = dtw(input.mfccs, template.mfccs) * (1 + LENGTH_PENALTY * lengthRatio);

        if (!perWord.has(template.word)) perWord.set(template.word, []);
        perWord.get(template.word).push({ voice: template.voice, distance });
    }

    // Score each word by its AVERAGE distance over all of its recordings.
    // Using only the single closest recording lets one voice that happens
    // to resemble the input decide the result on its own.
    const ranking = [...perWord.entries()].map(([word, matches]) => {
        const best = matches.reduce((a, b) => (b.distance < a.distance ? b : a));

        return {
            word,
            distance: matches.reduce((total, m) => total + m.distance, 0) / matches.length,
            best
        };
    }).sort((a, b) => a.distance - b.distance);

    console.log(`\nClosest words (average DTW distance over ${templates.length} reference recordings, lower = closer):`);

    ranking.slice(0, 5).forEach(({ word, distance, best }, i) => {
        console.log(
            `  ${i + 1}. ${word.padEnd(8)} ${distance.toFixed(2).padStart(6)}` +
            `   (closest single recording: ${best.voice}, ${best.distance.toFixed(2)})`
        );
    });

    const [first, second] = ranking;
    const margin = ((second.distance - first.distance) / second.distance) * 100;

    console.log(`\nFinal Text: ${first.word}`);
    console.log(`Margin over "${second.word}": ${margin.toFixed(0)}%${margin < 5 ? " (low - this could be wrong)" : ""}`);

    await playback;
}

main().catch((error) => {
    console.error("Failed:", error.message);
    process.exitCode = 1;
});
