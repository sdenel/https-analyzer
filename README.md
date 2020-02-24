# Usage examples
```bash
cat stdin_example.com | docker run -i sdenel/https-analyzer [--dns-server 8.8.8.8]
echo "google.com" | docker run -i sdenel/https-analyzer --dns-server 8.8.8.8 | tee output.json
docker run -i sdenel/http-analyzer --generate-html-from-json > output.html
```

# TODO
* extract HTML generation as a function
* Extract certificate informations + link to crt.sh. See https://stackoverflow.com/a/7691293/1795027