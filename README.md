# Usage examples
```bash
cat stdin_example.com | docker run -i sdenel/https-analyzer [--dns-server 8.8.8.8]
echo "google.com" | docker run -i sdenel/https-analyzer --dns-server 8.8.8.8 --output html > output.html
```

# Still TODO...
* Jinja template for html