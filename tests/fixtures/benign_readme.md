# VectorStore

A lightweight in-memory vector store for prototyping retrieval pipelines.

## Features

- Stores embeddings alongside document metadata.
- Cosine similarity search with optional top-k filtering.
- Serialization to JSON for small corpora.

## Usage

The library exposes a single `VectorStore` class. Documents are added with
their precomputed embeddings, and queries return ranked matches. The project
is intended for experiments and teaching, not production workloads.

## Configuration

The default index type is flat search. For larger collections, an optional
index module provides approximate search. Results include the document
identifier, the similarity score, and the stored metadata.

## License

MIT. See LICENSE for details.
