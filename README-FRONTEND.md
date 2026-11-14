# TRACELYT AI frontend

This is a vanilla HTML/CSS/JavaScript frontend for the existing Express + PostgreSQL backend.

## Run locally

1. Keep your backend running on `http://localhost:4000`.
2. Open a second terminal in the `tracelyt` folder.
3. Start a static server from the frontend folder:
   - Python: `python -m http.server 5500`
   - or VS Code Live Server.
4. Open `http://localhost:5500`.
5. In the frontend, open **Settings** and confirm the API URL is `http://localhost:4000`.

## CORS

Set `FRONTEND_ORIGIN=http://localhost:5500` in the backend `.env` (or use the exact Live Server origin, commonly `http://127.0.0.1:5500`). Restart the backend after changing `.env`.

## Implemented backend integration

- Health check and case list/create/open
- Add and list SMS, WhatsApp, URL, UPI, note and screenshot evidence
- Run the real rule-based analysis endpoint
- Read extracted entities, risk findings, relationship graph and timeline
- Download the backend-generated PDF report
- Delete evidence

## Honest limitations in the supplied backend

- Screenshot OCR is not installed. Screenshot files are stored, but text must be entered manually before analysis.
- Risk output is a transparent rule-based indicator assessment, not an AI fraud probability.
- Relationship edges are created only by the backend's implemented shared-identifier logic.
- No live threat-intelligence feed, external domain scan, phone-number ownership lookup, bank freeze, police dispatch, I4C/NCRP submission, legal certification or automated enforcement action is implemented in the supplied backend. The frontend does not claim these actions occurred.

## Deploying

Host the `frontend` folder as a static site. Set the backend `FRONTEND_ORIGIN` to the deployed frontend origin and configure the frontend API URL under Settings to the deployed backend URL. Use HTTPS for both.

## Explainability layer (insight.js)

Added on top of the existing API, with no backend changes and no new scoring:

- **Threat Findings**: "why this rating" summary, indicators grouped by category, each shown with the triggering text highlighted in its source evidence and a "Trace to source" link.
- **Relationship Graph**: click a node (mouse or keyboard) for why it was detected, supporting evidence, connected entities and related indicators.
- **Evidence Vault**: "Verify findings" shows the original text with extracted entities highlighted, the reason each was detected, and the indicators attributed to that item.
- **Case Summary** (and a compact card on Overview): totals, suspicious entities, relationships, risk level, a rule-based recommended next action, and "Copy as text".

Backend addition (services/riskAnalyzer.js): each finding now also carries `entity_key` (the graph node id that triggered it) and the risk result carries `rating_basis` with a plain-language explanation of exactly why the level was assigned. Scoring itself is unchanged. `npm test` in backend covers it.

The frontend falls back gracefully if these fields are absent (text match, then evidence type for linking findings).
