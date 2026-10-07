# Notes on indirect prompt injection research

Recent work studies a class of attacks in which third-party documents
embedded in retrieval corpora try to steer model behavior. A canonical
example quoted in the literature is the phrase "ignore all previous
instructions", which researchers use to demonstrate how retrieved text can
conflict with system-level directives.

The threat model assumes an attacker can publish content that is later
ingested by a retrieval pipeline. Defenses discussed in these papers include
input sanitization, instruction hierarchies, and detection of anomalous
directives in retrieved context. Evaluation typically measures attack
success rate before and after a proposed mitigation, as reported in several
survey papers on language model security.

References: Greshake et al. (2023) on indirect prompt injection; follow-up
benchmark studies published in 2024.
