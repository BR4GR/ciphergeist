#!/bin/env bash

echo "Running tests with coverage..."
uv run python -m pytest tests --cov --cov-config=pyproject.toml --cov-report=term-missing
if [ $? -ne 0 ]; then
  echo "Tests failed. Aborting commit."
  exit 1
fi

echo "Running make check..."
make check
if [ $? -ne 0 ]; then
  echo "Make check failed. Aborting commit."
  exit 1
fi

git add .

read -p "Enter commit message: " commit_message
git commit -m "$commit_message"

git push
