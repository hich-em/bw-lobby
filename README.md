# Lobby service (deploy this, not the game)

1. Put this folder in a GitHub repo -> Render.com (New > Web Service > Docker, free plan) or Railway.
2. When it is live, open https://YOUR-APP/signal/health : you should see JSON.
3. Your game address for Netlify is then: wss://YOUR-APP/signal
4. Optional env vars: ALLOWED_ORIGINS=https://your-site.netlify.app
   TURN_URLS / TURN_USERNAME / TURN_CREDENTIAL (a TURN relay, so everyone can connect)
