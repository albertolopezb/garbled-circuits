# Garbled Circuits — Yao's Millionaires' Problem

A from-scratch Python implementation of Yao's garbled circuits protocol,
letting two parties compare their private inputs without revealing them.

Alice has `a`, Bob has `b`. Both learn whether `a > b`. Neither learns
anything else about the other's number.

## Why this is interesting

Garbled circuits are the foundation of secure multi-party computation:
any boolean circuit can be evaluated jointly without the parties sharing
their inputs. The same idea underpins privacy-preserving machine learning
and private set intersection.

This implementation has no cryptographic dependencies — the garbling, the
oblivious transfer and the wire labels are all written out, so the protocol
can be read end to end.

## What is implemented

- **Garbled circuit construction** — a comparison circuit built from
  garbled gates, with random wire labels and encrypted truth tables.
- **Oblivious transfer** — RSA-based 1-out-of-2 OT (Even–Goldreich–Lempel),
  so Bob gets the label for his input bit without Alice learning which,
  and without Bob learning the other label.
- **Client/server execution** — the two parties run as separate processes
  and exchange real messages over a socket.
- **Traffic inspection** — every message can be dumped and replayed, to
  show that nothing on the wire reveals either input.

## Running it

```bash
# Terminal 1 — Alice
python millonarios.py alicia --bits 8

# Terminal 2 — Bob
python millonarios.py bob --bits 8

# Walk through the protocol one step at a time
python millonarios.py alicia --bits 8 --paso-a-paso

# Save the exchanged messages, then inspect them
python millonarios.py alicia --bits 8 --guardar-trafico
python millonarios.py ver-trafico
```

## Talk

`presentation.pdf` is a 35-minute talk on the protocol: construction,
oblivious transfer, the comparison with secret sharing, and where garbled
circuits show up in privacy-preserving machine learning.

## References

- A. C. Yao, *Protocols for Secure Computations*, FOCS 1982.
- S. Even, O. Goldreich, A. Lempel, *A Randomized Protocol for Signing
  Contracts*, 1985.
