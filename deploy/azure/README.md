# Deploying Phylax on Azure Container Apps

Phylax is one container. GitHub builds it and keeps it in the GitHub Container Registry (ghcr.io); Azure Container Apps runs it and puts HTTPS in front of it.
This guide was written without access to an Azure account, so every command below is untested here: if one fails, paste me its output and I will fix the guide.

```
Flwn backend ──https + API key──►  Azure Container Apps (1 copy of the Phylax container)  ──►  Azure AI Foundry (Decision-1, GPT-6 Astra)
                                          ▲ image pulled from ghcr.io/mennareda1/flwn-phylax
```

## The approval model (what "human approval" means in this deployment)

Phylax **never changes a file**. The service only reads the text it is sent, and returns findings and proposed corrections; it has no way to write anywhere.
Applying a correction happens in the CLIENT (the review client, an agent's tools, a terminal), and the client refuses to write unless a person says yes to that file's
diff. So switching corrections on in production does not give anyone the ability to change code without a person approving it.

## 1. Publish the image (once, then for every release)

Make sure CI is green on `main` (the Actions tab), then:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

The "Publish image" workflow builds the image, **starts it and runs `deploy/smoke.py` against it**, and only then publishes it as
`ghcr.io/mennareda1/flwn-phylax:v0.1.0` (and `:latest`). Watch it in the Actions tab.

The image contains no secrets, only the service and its pinned packages, so it is fine for the package to be public. After the first publish: GitHub, your profile,
Packages, `flwn-phylax`, Package settings, **Change visibility: Public** (if it is not already). A public image means Azure needs no registry password. If you keep it
private, Azure needs a read-only token: add `--registry-server ghcr.io --registry-username <you> --registry-password <a token with read:packages>` to the create command.

## 2. Get ready

```powershell
az login
az extension add --name containerapp --upgrade
az provider register --namespace Microsoft.App
az provider register --namespace Microsoft.OperationalInsights
```

Make the keys (the first is the key Flwn's backend will use; it is shown once, store it in a password manager):

```powershell
python -m security_service.api --new-key
```

It prints a line to use as `SERVICE_API_KEYS`, for example `flwn-ai:scan+fix+read:<the key>`. Put the values in variables for the next command (so they never go into a file):

```powershell
$KEYS   = "flwn-ai:scan+fix+read:<the key it printed>"
$FOUNDRY = "<the Azure AI Foundry key>"
```

## 3. Create the app

Pick one region and use it everywhere (close to your Foundry resource).

```powershell
az group create --name rg-phylax --location westeurope
az containerapp env create --name phylax-env --resource-group rg-phylax --location westeurope

az containerapp create --name phylax --resource-group rg-phylax --environment phylax-env `
  --image ghcr.io/mennareda1/flwn-phylax:v0.1.0 `
  --target-port 8080 --ingress external `
  --min-replicas 1 --max-replicas 1 --cpu 1 --memory 2Gi `
  --secrets "phylax-keys=$KEYS" "foundry-key=$FOUNDRY" `
  --env-vars SERVICE_HOST=0.0.0.0 SERVICE_PORT=8080 SERVICE_API_KEYS=secretref:phylax-keys FOUNDRY_API_KEY=secretref:foundry-key `
    FOUNDRY_ENDPOINT=https://aif-flwn-fc-01.services.ai.azure.com DECISION1_DEPLOYMENT=decision-1 CORRECTOR_DEPLOYMENT=gpt-6-astra `
    CLASSIFIER_ENABLED=true CLASSIFIER_LANGUAGES=python SERVICE_FIXES_ENABLED=true SERVICE_FIX_RATE_LIMIT_PER_MINUTE=10
```

`deploy/azure/production.env.example` lists every setting with a comment. **Run exactly ONE copy** (`--min-replicas 1 --max-replicas 1`): scans are kept in memory, so a
second copy would not know the first one's scans.

Find the address:

```powershell
az containerapp show --name phylax --resource-group rg-phylax --query properties.configuration.ingress.fqdn --output tsv
```

## 4. Check it works

```powershell
$env:PHYLAX_API_KEY = "<the key only, without the flwn-ai:scan+fix+read: part>"
python deploy\smoke.py --url https://<the address>
python deploy\smoke.py --url https://<the address> --fix       # also asks for one correction (a few cents)
```

Every line should say PASS. The first one is quick; `--fix` takes a few seconds. If a check fails, the line says what to look at.

## 5. Day-two tasks

| Task | How |
|---|---|
| See the logs | `az containerapp logs show --name phylax --resource-group rg-phylax --follow` (one line per request; no code or keys are ever logged) |
| Release a new version | tag `v0.1.1`, wait for the workflow, then `az containerapp update --name phylax --resource-group rg-phylax --image ghcr.io/mennareda1/flwn-phylax:v0.1.1` |
| Roll back | the same command with the previous tag |
| Change a setting | `az containerapp update --name phylax --resource-group rg-phylax --set-env-vars NAME=value` |
| Rotate the API key | make a new key; `az containerapp secret set --name phylax --resource-group rg-phylax --secrets "phylax-keys=<new line>"`; then `az containerapp revision restart` (give Flwn the new key first, or accept a short gap). To rotate without a gap, put BOTH keys in `SERVICE_API_KEYS` (comma separated), switch Flwn, then remove the old one |
| Limit who can call it | `az containerapp ingress access-restriction set --name phylax --resource-group rg-phylax --rule-name flwn --ip-address <Flwn backend IP>/32 --action Allow` |
| Add a language to Decision-1 | only after that language passes its held-out evaluation: set `CLASSIFIER_LANGUAGES=python,javascript` |
| Save credits while idle | `--min-replicas 0` lets it sleep (the first call after a pause takes several seconds, and scans in progress are forgotten). Use 1 on demo day |

## 6. What to know before relying on it

- **A restart forgets every scan.** Scans live only in memory (24 hours at most). A client that gets "not found" for a scan simply scans again; the review client does.
- **One copy only**, for the same reason. Scaling out needs a shared store first (not built).
- **HTTPS is the platform's.** The container itself speaks plain http inside Azure's network; never publish it any other way.
- **The service refuses to start without an API key**, so it can never be left open by mistake.
- **Cost:** an always-on copy is billed all the time; the Foundry model calls (Decision-1 is a fraction of a cent per scan, a correction is about 1 to 3 cents) are billed by Foundry. Check Azure's pricing calculator for your region.
- **Decision-1 runs for Python only** (the only language that has passed its held-out evaluation). JavaScript, TypeScript and every language added later are covered by the rules alone until they pass theirs.
