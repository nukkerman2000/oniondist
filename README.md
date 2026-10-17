# oniondist

Distributed **.onion vanity address** search — a light, Hashtopolis-style pool.

A central coordinator hands out contiguous ranges of the search keyspace to many
agents (GPU or CPU). Agents report progress and submit hits; the coordinator
renders the `.onion` and shows everything on a live dashboard.

Every hit is written to disk as a **ready-to-use hidden service directory**, both
on the agent that found it and on the coordinator:

```
keys/<pattern>/<onion>/hostname
                       hs_ed25519_secret_key
                       hs_ed25519_public_key
```

(Pick the root with `--keys DIR`, default `keys`.) This is exactly the layout
`util/genpubs.py` produces, so tor can host it as-is.

```
                 +-------------------+
   agents  --->  |  server.py        |  <--- public dashboard  http://host:8080/
 (gpu / cpu)     |  work chunks, DB  |  <--- admin panel       http://host:8080/admin
                 +-------------------+
```

## Components

| Path                | What it is                                                        |
|---------------------|-------------------------------------------------------------------|
| `server/server.py`  | Coordinator: assigns work, stores hits, serves dashboards + admin. Stdlib only. |
| `src/agent_gpu.cu`  | Distributed GPU agent (`vanity_gpu`). Needs CUDA.                 |
| `src/main_cpu.cpp`  | Portable CPU client (`vanity_cpu`). No CUDA needed.               |
| `src/search_common.h` | Shared CPU-side crypto primitives.                             |
| `src/hs_store.h`    | Renders the full `.onion` and writes hidden-service folders.      |
| `src/dist.h`        | Tiny dependency-free HTTP/JSON client.                            |
| `src/main.cu`       | The original single-machine GPU searcher (`vanity_torv3_cuda`).   |
| `util/onion.py`     | hex secret key -> `.onion` hostname (PyNaCl).                     |

## How work is split

Each **counter** `c` deterministically yields 10 candidate addresses:

```
key = keccak( key_template ^ c )        (12 rounds)
md  = sc_reduce32(key)
P   = md * B
slot s:  P += 8*B ; pubkey = tobytes(P) ; secret = md + 8*(s+1)
```

The coordinator keeps a cursor **per task** and hands each agent a contiguous
`[start, start+count)` range. GPU and CPU agents use the same counter space, so
ranges are interchangeable; the coordinator picks the range size per agent kind
(GPU chunk `2^26`, CPU chunk `2^16` by default) — see **Configuration** for the
auto-by-weights / manual chunk sizing.

## Tasks (multi-task pool)

The pool can hunt several patterns at once; each pattern is a **task**:

- **1 active task** — every approved worker is auto-assigned to it.
- **2 or more tasks** — an admin must assign each worker to exactly one task
  in the panel (1 worker = 1 task). Unassigned workers stay online but idle.

Create tasks either at startup (`--pattern aistorys`, seeds one if missing) or
anytime from the admin panel. Each task has its own progress, rate, ETA and
found count, and can be started/stopped individually.

Tasks are never hard-deleted from the running list: **Archive** hides a task
(and unassigns its workers) into the **Archive (hidden tasks)** section, where it
can be **Restored** (back to active) or **Deleted forever**. Found keys and their
certificate folders are always kept. Re-creating an archived pattern restores it.

## Auth & admin

Two secrets, both optional (an unset secret means that surface is open — don't
do that on a public network):

- `--token` — shared **agent** secret. A worker that presents it (header
  `Authorization: Bearer <token>` or `?token=`) is **auto-approved**.
- `--admin-token` — secret for `/admin` and `/api/admin/*` (defaults to `--token`).

Workers **without** a valid token still connect and show up **online as
`pending`**, but get **no work** until an admin approves them in the panel.

The public dashboard `http://host:8080/` shows the tasks and the **online**
workers only. It makes the pool state explicit: **WORKING** (at least one worker
actively searching), **WAITING** (workers online but stopped/unassigned, or none
online), or **POOL PAUSED**; the reported rate/ETA count only actually-working
workers, so a stopped worker no longer shows a stale speed. `GET /api/status`
carries `state` (`running`/`idle`/`paused`/`empty`), `online_count`,
`working_count`, and a per-client `working` flag. The admin panel
`http://host:8080/admin` (needs the admin token) additionally shows **all
registered workers** and lets you:

- start/stop the whole pool, or each task or worker individually;
- approve/revoke workers, assign each worker to a task;
- manage **chunk sizes** (see below) and see **which worker found each key**;
- download the hidden-service **certificate** (hostname + keys) as a `.zip`.

## Configuration

The coordinator reads a JSON config file (default `server/config.json`, override
with `--config`; see `server/config.example.json`). Any CLI flag overrides the
file. Missing file / missing keys fall back to defaults.

```json
{
  "host": "0.0.0.0",
  "port": 8090,
  "db": "oniondist.db",
  "keys": "keys",
  "expand": 10,
  "token": "AGENT_SECRET",
  "admin_token": "ADMIN_SECRET",
  "chunks": {
    "mode": "auto",
    "base": 65536,
    "weights": { "gpu": 1024, "cpu": 1 },
    "manual":  { "gpu": 67108864, "cpu": 65536 }
  }
}
```

**Chunk management.** Each work request hands an agent a range of `count`
counters. `count` is chosen per agent kind:

- **`mode: "auto"` (default)** — sized **by weights**: `count = base * weights[kind]`.
  With the defaults (`base=65536`, `gpu=1024`, `cpu=1`) a GPU worker gets
  `2^26` counters and a CPU worker `2^16`. Bigger weight = bigger, less-frequent
  chunks (good for fast GPUs); smaller = finer-grained, more responsive chunks.
- **`mode: "manual"`** — use the exact `manual[kind]` sizes, weights ignored.

Both modes can be set in the file, on the command line (`--chunk-mode`,
`--chunk-base`, `--gpu-weight`, `--cpu-weight`, `--gpu-chunk`, `--cpu-chunk`),
or **changed live** in the admin panel's **Chunks** section. Runtime changes are
written back to the config file (other keys are preserved), so they survive a
restart. The public dashboard shows the active sizes; `GET /api/status` carries a
`chunks` object (`mode`, `base`, `weights`, `manual`, resolved `sizes`).


## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CUDA_ARCHITECTURES=86      # adjust / omit for CPU-only hosts
cmake --build build -j
```

Produces `build/vanity_cpu`, and `build/vanity_gpu` + `build/vanity_torv3_cuda`
where a CUDA compiler is available. On a machine with no CUDA, only `vanity_cpu`
is built.

## Run

Start the coordinator. Settings (port, tokens, chunks) come from
`server/config.json`; `--pattern` seeds the first task:

```bash
python3 server/server.py --pattern aistorys
```

Or pass everything on the command line instead of a config file:

```bash
python3 server/server.py --pattern aistorys --port 8080 \
    --token AGENT_SECRET --admin-token ADMIN_SECRET \
    --chunk-mode auto --gpu-weight 1024 --cpu-weight 1
```

Join agents (each presents the agent token; `--keys DIR` to change output dir):

```bash
# GPU rig (one per machine; the server supplies the pattern)
./build/vanity_gpu --server http://192.168.7.222:8080 --name rig-3060 --token AGENT_SECRET -i

# any CPU machine
./build/vanity_cpu --server http://192.168.7.222:8080 --name vps-1 --token AGENT_SECRET -t 8
```

Local single-machine search (unchanged behaviour, no coordinator):

```bash
./build/vanity_torv3_cuda -i aistorys            # GPU + CPU pool
./build/vanity_cpu -t 8 -i aistorys              # CPU only, standalone
```

Open `http://192.168.7.222:8080/` for the public dashboard, and
`http://192.168.7.222:8080/admin?token=ADMIN_SECRET` for the admin panel.

## Verify a hit

```bash
python3 util/onion.py <hex64> --check aistorys
```

## Notes / limitations

- The coordinator hands out work once; if an agent dies mid-chunk that range is
  skipped (up to one chunk of lost work). Fine for a hunt, not for exactness.
- `EXPAND=10` means each counter tests 10 addresses; expected counters to test
  for a prefix of length `L` is `32^L / 10`.
- The GPU kernels have a known benign write-overlap between neighbouring indices
  at slots 0 and 4 of each batch; those rare hits may be wrong. The dashboard
  marks `valid` hits (onion actually matching the prefix) so bad ones are visible.
- Worker approval state, task assignment and per-worker start/stop are kept
  server-side: "stop" means the worker keeps polling but receives no work.
