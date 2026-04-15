import fs from "fs";
import wav from "node-wav";
import { fft } from "fft-js";


function loadAudio(filePath) {
    const buffer = fs.readFileSync(filePath);
    const decoded = wav.decode(buffer);

    // Mono channel
    const waveform = decoded.channelData[0]; // Float32Array
    const sampleRate = decoded.sampleRate;

    return { waveform, sampleRate };
}

function computeSpectrogram(waveform, frameSize = 512, hopSize = 256) {
    const spectrogram = [];

    for (let i = 0; i < waveform.length - frameSize; i += hopSize) {
        const frame = waveform.slice(i, i + frameSize);

        // Apply FFT
        const phasors = fft(frame);

        // Magnitude
        const magnitudes = phasors.map(([re, im]) =>
            Math.sqrt(re * re + im * im)
        );

        spectrogram.push(magnitudes);
    }

    return spectrogram;
}

function fakeModelInference(spectrogram) {
    // Simulated token output
    return ["h", "e", "l", "l", "o"];
}

function decode(tokens) {
    return tokens.join("");
}

async function main() {
    const { waveform } = loadAudio("./audio.wav");

    const spectrogram = computeSpectrogram(waveform);

    const tokens = fakeModelInference(spectrogram);

    const text = decode(tokens);

    console.log("Final Text:", text);
}

main();