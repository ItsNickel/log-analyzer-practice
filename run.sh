#!/usr/bin/env bash
python3 -m log_analyzer.analyzer examples/sample_access.log --out-json outputs/alerts.json --out-csv outputs/alerts.csv
