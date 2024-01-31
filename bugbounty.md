# Subdomain enumeration
Active scan -> https://github.com/projectdiscovery/subfinder

Example
```bash
subfinder -d my-domain.com -all -o subfiner.mydomains.out
```

Passive scan -> https://github.com/projectdiscovery/dnsx

Example
```bash
dnsx -d my-domain.com -w my-wordlist.txt -o dnsx.mydomains.out
```
```bash
cat {dnsx,subfinder}.mydomains.out | sort -u | tee final.mydomains.out
```

# Probing
httpx -> https://github.com/projectdiscovery/httpx

```bash
cat final.mydomains.out | httpx -status-code -location -title -tech-detect -o httpx.mydomains.out
```

# Port Scan
naabu -> https://github.com/projectdiscovery/naabu

```bash
naabu -l final.mydomains.out -o naabu.ports.out
```

# Run Nuclei
nuclei -> naabu -> https://github.com/projectdiscovery/naabu

```bash
nuclei -l finall.mydomain.out -o nuclei.out
```

# Run feroxbuster
feroxbuster -> https://github.com/epi052/feroxbuster

```bash
feroxbuster --url httpx.filterd-url.out --depth 2 --wordlist my-wordlist.txt --threads 100 -C 404
```

# Crawl sites
katana -> https://github.com/projectdiscovery/katana

```bash
katana -jc -u https://my-url.com -o katana.out -aff
```
