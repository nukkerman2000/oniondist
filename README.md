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
   agents  --->  |  server.py        |  <--- dashboard (http://host:8080/)
 (gpu / cpu)     |  work chunks, DB  |
                 +-------------------+
```

## Components

| Path                | What it is                                                        |
|---------------------|-------------------------------------------------------------------|
| `server/server.py`  | Coordinator: assigns work, stores hits, serves the dashboard. Stdlib only. |
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

The coordinator keeps a global cursor and hands each agent a contiguous
`[start, start+count)` range. GPU and CPU agents use the same counter space, so
ranges are interchangeable; large ranges (GPU chunk `2^26`) and small ones
(CPU chunk `2^16`) keep both fast and responsive.

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

Start the coordinator (pick your target prefix):

```bash
python3 server/server.py --pattern aistorys --port 8080
```

Join agents (each writes its finds under its own `keys/`; `--keys DIR` to change):

```bash
# GPU rig (one per machine; no pattern needed, the server supplies it)
./build/vanity_gpu --server http://192.168.7.222:8080 --name rig-3060 -i

# any CPU machine
./build/vanity_cpu --server http://192.168.7.222:8080 --name vps-1 -t 8
```

Local single-machine search (unchanged behaviour):

```bash
./build/vanity_torv3_cuda -i aistorys            # GPU + CPU pool
./build/vanity_cpu -t 8 -i aistorys              # CPU only, standalone
```

Open `http://192.168.7.222:8080/` for the live dashboard (agents, pool rate,
ETA, found keys).

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
