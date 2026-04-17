# SSRF Guardian Desktop

A standalone desktop application for real-time SSRF protection monitoring and control.

## Features

- **Live Attack Feed**: Real-time monitoring of all blocked SSRF attempts
- **AI-Powered Analysis**: Groq AI explanations for every attack
- **Mutation Engine**: Generate 50+ bypass variants of any URL
- **Chat Analyst**: Natural language queries about attack patterns
- **Domain Fuzzer**: Automated vulnerability scanning
- **Preflight Analysis**: Client-side validation before requests

## Prerequisites

- Node.js 18+
- Guardian Backend API running on `http://localhost:3000`

## Installation

```bash
cd frontend
npm install
```

## Development

```bash
# Start development server
npm run electron-dev

# Or separately:
npm run dev          # Start Vite dev server
npm run electron     # Start Electron app
```

## Building

```bash
# Build for current platform
npm run dist

# Build for specific platforms
npm run dist-win     # Windows
npm run dist-mac     # macOS
npm run dist-linux   # Linux
```

## Usage

1. Ensure the Guardian backend is running on `http://localhost:3000`
2. Launch the desktop app
3. Monitor real-time attacks in the Live Feed
4. Use AI tools to analyze and generate attack variants
5. Configure protection settings

## Architecture

- **Frontend**: React + Vite
- **Desktop**: Electron
- **Backend**: Node.js Express API
- **AI**: Groq API integration (optional)

## Security Pipeline

Every request passes through 7 stages of validation:
1. Scheme validation (http/https only)
2. DNS resolution & IP pinning
3. IP canonicalization & private network blocking
4. Allowlist checking
5. Manual redirect handling
6. Post-connection IP verification
7. Response size limiting
