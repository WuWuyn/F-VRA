# F-VRA Web

Frontend dashboard for F-VRA, a reachability-aware SCA and vulnerability impact analysis product.

## Features

- Portfolio dashboard for projects, packages, CVEs, scans, integrations, and settings.
- Interactive Graph Explorer powered by `@xyflow/react`.
- Draggable graph nodes, zoom, pan, fit view, minimap, and controls.
- Project/CVE impact graphs plus function-level call path visualization.
- F-VRA logo and blue/white visual identity.

## Requirements

- Node.js 20+
- npm

## Local Development

```bash
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The Vite dev server proxies `/api` to the backend API at
`http://localhost:8000`, so frontend code can call same-origin paths such as
`/api/health` in development and production.

## Validation

```bash
npm run lint
npm run build
```

## Docker

Build the production image:

```bash
docker build -t f-vra-web .
```

Run it:

```bash
docker run --rm -p 8080:80 f-vra-web
```

Open:

```text
http://localhost:8080
```

The container uses a multi-stage build with Node for compilation and Nginx for serving the static SPA with route fallback.
Nginx also proxies `/api/` to `http://f-vra-api:8000/api/`, allowing one public
domain to serve both the frontend and backend when the backend container or
service is named `f-vra-api`.
