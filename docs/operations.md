# TSL Operations

Local stack:

```bash
docker compose up
```

Core checks:

```bash
npm run build
npm test
npm run contracts:test
npm run cli -- vector
```

Settlement demo:

```bash
npm run chain
npm run contracts:deploy:local
npm run cli -- demo-settlement --registry-address 0x5FbDB2315678afecb367f032d93F642f64180aa3
```
