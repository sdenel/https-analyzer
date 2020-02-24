# Usage examples
```bash
cat stdin_example.com | docker run -i sdenel/https-analyzer [--dns-server 8.8.8.8]
echo "google.com" | docker run -i sdenel/https-analyzer --dns-server 8.8.8.8 | tee output.json
echo "google.com" | docker run -i sdenel/https-analyzer --dns-server dns-over-https | tee output.json
```

# TODO
* extract HTML generation as a function
* Extract certificate informations + link to crt.sh. See https://stackoverflow.com/a/7691293/1795027